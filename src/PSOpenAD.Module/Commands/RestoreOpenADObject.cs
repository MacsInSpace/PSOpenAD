using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsData.Restore, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(OpenADObject))]
public class RestoreOpenADObject : OpenADSessionCmdletBase
{
    private StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    private const string LAST_KNOWN_RDN = "msDS-LastKnownRDN";
    private const string LAST_KNOWN_PARENT = "lastKnownParent";
    private const string IS_DELETED = "isDeleted";
    private const string IS_RECYCLED = "isRecycled";
    private const string DISTINGUISHED_NAME = "distinguishedName";

    #region Restore-OpenADObject Parameters

    /// <summary>
    /// The distinguished name of the deleted object, as found with
    /// <c>Get-OpenADObject -IncludeDeletedObjects</c>. This is the mangled
    /// name inside the Deleted Objects container, not the original one.
    /// </summary>
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public ADObjectIdentity? Identity { get; set; }

    /// <summary>
    /// Restore to this container instead of the one the object was deleted
    /// from. Use when the original parent has itself been deleted, which
    /// otherwise fails with "the object's parent is deleted".
    /// </summary>
    [Parameter]
    public string? TargetPath { get; set; }

    /// <summary>
    /// Restore under this name instead of the one recorded in
    /// msDS-LastKnownRDN. Use when an object of that name has been recreated
    /// since the deletion.
    /// </summary>
    [Parameter]
    public string? NewName { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);

        // Every request here needs LDAP_SERVER_SHOW_DELETED_OID. A deleted
        // object is invisible without it, so both the lookup and the modify
        // would otherwise fail with "no such object".
        List<LDAPControl> controls = new() { new ShowDeleted(true) };

        string? entry = Identity.DistinguishedName;
        if (entry == null)
        {
            WriteError(new ErrorRecord(
                new ArgumentException(
                    "Restore-OpenADObject requires the distinguished name of the deleted object, " +
                    "as returned by Get-OpenADObject -IncludeDeletedObjects."),
                "RestoreOpenADObjectIdentityNotDN",
                ErrorCategory.InvalidArgument,
                Identity));
            return;
        }

        SearchResultEntry? deleted = Operations.LdapSearchRequest(
            session.Connection,
            entry,
            SearchScope.Base,
            0,
            session.OperationTimeout,
            new FilterPresent("objectClass"),
            new[] { LAST_KNOWN_RDN, LAST_KNOWN_PARENT, IS_DELETED, IS_RECYCLED },
            controls,
            CancelToken,
            this,
            false
        ).FirstOrDefault();

        if (deleted == null)
        {
            WriteError(new ErrorRecord(
                new ItemNotFoundException($"Cannot find a deleted object with the identity '{entry}'"),
                "RestoreOpenADObjectNotFound",
                ErrorCategory.ObjectNotFound,
                entry));
            return;
        }

        // A recycled object has already had its attributes stripped; the
        // directory will refuse the restore and the caller deserves to know
        // why rather than reading a bare WILL_NOT_PERFORM.
        if (GetFirstValue(deleted, IS_RECYCLED) != null)
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException(
                    $"'{entry}' has been recycled, not merely deleted. Its attributes were removed when the " +
                    "deleted object lifetime expired and it can no longer be restored; recover it from a backup."),
                "RestoreOpenADObjectRecycled",
                ErrorCategory.InvalidOperation,
                entry));
            return;
        }

        string? rdnValue = NewName ?? GetFirstValue(deleted, LAST_KNOWN_RDN);
        if (string.IsNullOrEmpty(rdnValue))
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException(
                    $"'{entry}' has no {LAST_KNOWN_RDN} to restore it under; supply -NewName."),
                "RestoreOpenADObjectNoRDN",
                ErrorCategory.InvalidOperation,
                entry));
            return;
        }

        string? parent = TargetPath ?? GetFirstValue(deleted, LAST_KNOWN_PARENT);
        if (string.IsNullOrEmpty(parent))
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException(
                    $"'{entry}' has no {LAST_KNOWN_PARENT} to restore it into; supply -TargetPath."),
                "RestoreOpenADObjectNoParent",
                ErrorCategory.InvalidOperation,
                entry));
            return;
        }

        // Keep the RDN attribute the object was deleted with - CN for most
        // things, OU for an organizational unit - rather than assuming CN.
        DistinguishedName parsed = DistinguishedName.Parse(entry);
        string rdnAttribute = parsed.RelativeNames.Length > 0
            ? parsed.RelativeNames[0].Values[0].Type
            : "CN";
        string newDN = $"{rdnAttribute}={EscapeRDNValue(rdnValue)},{parent}";

        WriteVerbose($"Restoring '{entry}' -> '{newDN}'");
        if (!ShouldProcess($"'{entry}' -> '{newDN}'", "Restore"))
        {
            return;
        }

        // The restore is one modify carrying both changes. Splitting it into
        // two requests does not work: removing isDeleted on its own leaves the
        // object in the Deleted Objects container in an invalid state.
        ModifyChange[] changes = new[]
        {
            new ModifyChange(
                ModifyOperation.Delete,
                new PartialAttribute(IS_DELETED, Array.Empty<byte[]>())),
            new ModifyChange(
                ModifyOperation.Replace,
                new PartialAttribute(DISTINGUISHED_NAME, new[] { Encoding.UTF8.GetBytes(newDN) })),
        };

        ModifyResponse resp = Operations.LdapModifyRequest(
            session.Connection,
            entry,
            changes,
            controls,
            CancelToken,
            this);
        if (resp.Result.ResultCode != LDAPResultCode.Success)
        {
            return;
        }

        if (!PassThru)
        {
            return;
        }

        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .ToHashSet(_caseInsensitiveComparer);

        WriteVerbose($"Getting PassThru result for '{newDN}'");
        SearchResultEntry? restored = Operations.LdapSearchRequest(
            session.Connection,
            newDN,
            SearchScope.Base,
            0,
            session.OperationTimeout,
            new FilterPresent("objectClass"),
            searchProperties.ToArray(),
            null,
            CancelToken,
            this,
            false
        ).FirstOrDefault();

        if (restored != null)
        {
            WriteObject(GetOpenADObject.CreateOutputObject(
                session,
                restored,
                searchProperties,
                null,
                this));
        }
    }

    private static string? GetFirstValue(SearchResultEntry entry, string name)
    {
        PartialAttribute? attr = entry.Attributes
            .FirstOrDefault(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));
        if (attr == null || attr.Values.Length == 0)
        {
            return null;
        }
        return Encoding.UTF8.GetString(attr.Values[0]);
    }

    /// <summary>
    /// Escape an RDN value per RFC 4514. A deleted object's last known RDN is
    /// whatever the object was called, so it can legitimately contain commas,
    /// plus signs and the rest.
    /// </summary>
    private static string EscapeRDNValue(string value)
    {
        StringBuilder sb = new(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            bool leadingOrTrailingSpace = c == ' ' && (i == 0 || i == value.Length - 1);
            if (c is '\\' or ',' or '+' or '"' or '<' or '>' or ';' or '=' ||
                (c == '#' && i == 0) ||
                leadingOrTrailingSpace)
            {
                sb.Append('\\');
            }
            sb.Append(c);
        }
        return sb.ToString();
    }
}
