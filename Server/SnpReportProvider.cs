namespace SevSnpDemo.Server;

/// <summary>
/// Requests SEV-SNP attestation reports from the AMD secure processor via the kernel's
/// configfs-tsm interface (<c>/sys/kernel/config/tsm/report</c>).
/// </summary>
/// <remarks>
/// configfs-tsm is preferred over the older <c>/dev/sev-guest</c> ioctl for two reasons: it is plain
/// file I/O, so there is no P/Invoke of a versioned ioctl struct to get subtly wrong, and it is the
/// TEE-agnostic interface, so the same code shape works for Intel TDX later.
///
/// Requires Linux 6.7 or newer with <c>CONFIG_TSM_REPORTS</c>, and write access to configfs — in
/// practice root. See the README for the check-and-mount steps.
/// </remarks>
public sealed class SnpReportProvider
{
    private const string ConfigFsReportRoot = "/sys/kernel/config/tsm/report";
    private const int ReportDataLength = 64;
    private const int ExpectedReportLength = 1184;

    // The PSP handles one report request at a time and is not fast. Serializing here keeps a burst of
    // client requests from turning into a pile of EBUSY failures.
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>The configfs-tsm directory exists. Necessary but <em>not</em> sufficient — see
    /// <see cref="Probe"/>.</summary>
    public static bool DirectoryExists => Directory.Exists(ConfigFsReportRoot);

    public sealed record ProbeResult(bool Ok, string Detail);

    /// <summary>
    /// Actively checks that a report can be requested, by creating and removing a configfs entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The mere existence of <c>/sys/kernel/config/tsm/report</c> proves only that the kernel's
    /// <c>tsm</c> core registered its configfs group. It does <b>not</b> prove that any TEE provider
    /// bound to it. When none has, the kernel's <c>tsm_report_make_item</c> fails the <c>mkdir</c> with
    /// <c>ENXIO</c> ("No such device or address") — so a server that only checked
    /// <see cref="DirectoryExists"/> starts cleanly and then fails every single request, which is the
    /// worst of both worlds.
    /// </para>
    /// <para>
    /// Creating a directory is the only way to find out; configfs exposes no read-only "is a provider
    /// bound" attribute. The probe is cheap — it does not write <c>inblob</c>, so no report is
    /// generated and the PSP is not involved.
    /// </para>
    /// </remarks>
    public static ProbeResult Probe()
    {
        if (!DirectoryExists)
        {
            return new(false,
                $"{ConfigFsReportRoot} does not exist. Needs Linux 6.7+ with CONFIG_TSM_REPORTS, and " +
                "configfs mounted: sudo mount -t configfs none /sys/kernel/config");
        }

        var entry = Path.Combine(ConfigFsReportRoot, $"probe-{Guid.NewGuid():N}");

        try
        {
            Directory.CreateDirectory(entry);
        }
        catch (IOException ex)
        {
            // ENXIO surfaces as a plain IOException; there is no dedicated .NET exception type, and the
            // errno is only in the message text.
            var looksLikeNoProvider =
                ex.Message.Contains("No such device or address", StringComparison.OrdinalIgnoreCase);

            return new(false, looksLikeNoProvider
                ? $"{ConfigFsReportRoot} exists but no TSM provider is bound to it (ENXIO on mkdir). " +
                  "The kernel's tsm core is loaded, but the sev-guest driver is not. Try " +
                  "`sudo modprobe sev-guest`, then check `ls -l /dev/sev-guest` and " +
                  "`dmesg | grep -i -E 'sev|snp'`. On Azure CVMs that boot behind the OpenHCL " +
                  "paravisor, /dev/sev-guest may not be exposed at all and attestation must go " +
                  "through the vTPM instead — see README, Troubleshooting."
                : $"Could not create a configfs-tsm entry: {ex.Message}");
        }
        catch (UnauthorizedAccessException)
        {
            return new(false, $"No write access to {ConfigFsReportRoot}. Run as root.");
        }

        try
        {
            var provider = TryReadAttribute(entry, "provider") ?? "(unreadable)";
            var floor = TryReadAttribute(entry, "privlevel_floor") ?? "(absent)";
            return new(true, $"provider={provider}, privlevel_floor={floor}");
        }
        finally
        {
            try { Directory.Delete(entry); } catch (IOException) { /* best effort */ }
        }
    }

    /// <summary>
    /// Requests a fresh attestation report over the supplied 64-byte REPORT_DATA.
    /// </summary>
    public async Task<byte[]> GetReportAsync(byte[] reportData, CancellationToken cancellationToken = default)
    {
        if (reportData.Length != ReportDataLength)
        {
            throw new ArgumentException(
                $"REPORT_DATA must be exactly {ReportDataLength} bytes, got {reportData.Length}.",
                nameof(reportData));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // A per-request directory keeps concurrent callers from clobbering each other's inblob.
            var entry = Path.Combine(ConfigFsReportRoot, $"demo-{Guid.NewGuid():N}");

            try
            {
                Directory.CreateDirectory(entry);
            }
            catch (IOException ex)
            {
                // Startup probes for this, so reaching it means the provider unbound while running.
                throw new PlatformNotSupportedException(
                    $"Could not create {entry}: {ex.Message}. {Probe().Detail}", ex);
            }

            try
            {
                AlignPrivilegeLevel(entry);

                await File.WriteAllBytesAsync(Path.Combine(entry, "inblob"), reportData, cancellationToken)
                    .ConfigureAwait(false);

                // Reading outblob is what actually triggers report generation, so it must follow the
                // inblob write. The kernel surfaces PSP failures as an error on this read.
                byte[] report;
                try
                {
                    report = await File.ReadAllBytesAsync(Path.Combine(entry, "outblob"), cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    throw new IOException(
                        $"Reading {entry}/outblob failed: {ex.Message}. " +
                        $"privlevel={TryReadAttribute(entry, "privlevel") ?? "?"}, " +
                        $"privlevel_floor={TryReadAttribute(entry, "privlevel_floor") ?? "(absent)"}, " +
                        $"provider={TryReadAttribute(entry, "provider") ?? "?"}. " +
                        "EINVAL here usually means privlevel is below the driver's floor; EBUSY means the " +
                        "PSP is saturated.", ex);
                }

                if (report.Length != ExpectedReportLength)
                {
                    throw new InvalidDataException(
                        $"Expected a {ExpectedReportLength}-byte SEV-SNP report, got {report.Length}. " +
                        "The TSM provider may not be sev_guest — check " +
                        $"`cat {entry}/provider`.");
                }

                return report;
            }
            finally
            {
                // configfs entries are directories; rmdir releases the slot.
                try { Directory.Delete(entry); } catch (IOException) { /* best effort */ }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Raises the requested privilege level to the driver's floor when the platform demands it.
    /// </summary>
    /// <remarks>
    /// configfs-tsm defaults <c>privlevel</c> to 0, and the sev-guest driver rejects a request below
    /// <c>privlevel_floor</c> with <c>EINVAL</c>. On Azure confidential VMs the floor is <b>not</b> 0:
    /// the guest runs at VMPL2 because Microsoft's paravisor owns VMPL0. So the out-of-the-box default
    /// fails on exactly the platform this demo targets, with an errno and no explanation.
    ///
    /// The floor is a lower bound the platform imposes, not something a caller can weaken, so adopting
    /// it is not a downgrade — asking for a level below it simply cannot succeed. The resulting VMPL
    /// appears in the report and the client prints it.
    ///
    /// <c>privlevel_floor</c> is absent on older kernels; in that case the default is left alone.
    /// </remarks>
    private static void AlignPrivilegeLevel(string entry)
    {
        if (TryReadAttribute(entry, "privlevel_floor") is not { } floorText ||
            !int.TryParse(floorText, out var floor) ||
            floor <= 0)
        {
            return;
        }

        try
        {
            File.WriteAllText(Path.Combine(entry, "privlevel"), floor.ToString());
        }
        catch (IOException)
        {
            // Leave the default and let the outblob read report the real failure.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string? TryReadAttribute(string entry, string name)
    {
        try
        {
            return File.ReadAllText(Path.Combine(entry, name)).Trim();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Reads the TSM provider name, e.g. "sev_guest". Diagnostic only.</summary>
    public static string? TryReadProvider()
    {
        try
        {
            var entry = Path.Combine(ConfigFsReportRoot, $"probe-{Guid.NewGuid():N}");
            Directory.CreateDirectory(entry);
            try
            {
                return File.ReadAllText(Path.Combine(entry, "provider")).Trim();
            }
            finally
            {
                try { Directory.Delete(entry); } catch (IOException) { }
            }
        }
        catch
        {
            return null;
        }
    }
}
