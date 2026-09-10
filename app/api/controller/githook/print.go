// Copyright 2023 Harness, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package githook

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/harness/gitness/app/api/controller/limiter"
	"github.com/harness/gitness/git"
	"github.com/harness/gitness/git/hook"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
)

var (
	colorScanHeader            = color.New(color.FgHiWhite, color.Underline)
	colorScanSummary           = color.New(color.FgHiRed, color.Bold)
	colorScanSummaryNoFindings = color.New(color.FgHiGreen, color.Bold)

	infoColor     = color.New(color.FgCyan)
	warningColor  = color.New(color.FgYellow)
	criticalColor = color.New(color.FgRed, color.Bold)
)

func printScanSecretsFindings(
	output *hook.Output,
	findings []secretFinding,
	multipleRefs bool,
	duration time.Duration,
) {
	findingsCnt := len(findings)

	// no results? output success and continue
	if findingsCnt == 0 {
		output.Messages = append(
			output.Messages,
			colorScanSummaryNoFindings.Sprintf("No secrets found")+
				fmt.Sprintf(" in %s", duration.Round(time.Millisecond)),
			"", "", // add two empty lines for making it visually more consumable
		)
		return
	}

	output.Messages = append(
		output.Messages,
		colorScanHeader.Sprintf(
			"Push contains %s:",
			singularOrPlural("secret", findingsCnt > 1),
		),
		"", // add empty line for making it visually more consumable
	)

	for _, finding := range findings {
		headerTxt := fmt.Sprintf("%s in %s:%d", finding.RuleID, finding.File, finding.StartLine)
		if finding.StartLine != finding.EndLine {
			headerTxt += fmt.Sprintf("-%d", finding.EndLine)
		}
		if multipleRefs {
			headerTxt += fmt.Sprintf(" [%s]", finding.Ref)
		}

		output.Messages = append(
			output.Messages,
			fmt.Sprintf("  %s", headerTxt),
			fmt.Sprintf("      Secret:       %s", finding.Secret),
			fmt.Sprintf("      Commit:       %s", finding.Commit),
			fmt.Sprintf("      Details:      %s", finding.Description),
			fmt.Sprintf("      Fingerprint:  %s", finding.Fingerprint),
			"", // add empty line for making it visually more consumable
		)
	}

	output.Messages = append(
		output.Messages,
		colorScanSummary.Sprintf(
			"%d %s found",
			findingsCnt,
			singularOrPlural("secret", findingsCnt > 1),
		)+fmt.Sprintf(" in %s", FMTDuration(time.Millisecond)),
		"", "", // add two empty lines for making it visually more consumable
	)
}

func FMTDuration(d time.Duration) string {
	const secondsRounding = time.Second / time.Duration(10)
	switch {
	case d <= time.Millisecond:
	// keep anything under a millisecond untouched
	case d < time.Second:
		d = d.Round(time.Millisecond) // round under a second to millisecondss
	case d < time.Minute:
		d = d.Round(secondsRounding) // round under a minute to .1 precision
	default:
		d = d.Round(time.Second) // keep rest at second precision
	}
	return d.String()
}

func printOversizeFiles(
	output *hook.Output,
	findOut *git.FindOversizeFilesOutput,
) {
	if output == nil || findOut == nil {
		return
	}

	if len(findOut.TotalsPerLimit) == 0 {
		return
	}

	// Deterministic ordering, largest limit first so that smaller limits
	// can reference the "aforementioned" files from higher limits.
	limits := make([]int64, 0, len(findOut.TotalsPerLimit))
	for limit := range findOut.TotalsPerLimit {
		limits = append(limits, limit)
	}
	slices.SortFunc(limits, func(a, b int64) int {
		return int(b - a)
	})

	var cumulativeTotal int64
	for _, limit := range limits {
		total := findOut.TotalsPerLimit[limit]
		if total == 0 {
			continue
		}

		files := findOut.FileInfosPerLimit[limit]

		header := fmt.Sprintf(
			"Push contains %d %s exceeding the size limit of %dB",
			total,
			singularOrPlural("file", total > 1),
			limit,
		)
		if cumulativeTotal > 0 {
			header += fmt.Sprintf(
				" (in addition to the %d %s above)",
				cumulativeTotal,
				singularOrPlural("file", cumulativeTotal > 1),
			)
		}
		output.Messages = append(
			output.Messages,
			colorScanHeader.Sprint(header+":"),
			"",
		)

		for _, file := range files {
			output.Messages = append(
				output.Messages,
				fmt.Sprintf("  %s", file.SHA),
				fmt.Sprintf("      Size: %dB", file.Size),
				"",
			)
		}

		// If capped, clarify how many are shown.
		if int64(len(files)) < total {
			output.Messages = append(
				output.Messages,
				colorScanSummary.Sprintf(
					"Showing %d of %d %s",
					len(files),
					total,
					singularOrPlural("file", total > 1),
				),
				"",
			)
		} else {
			output.Messages = append(output.Messages, "")
		}

		cumulativeTotal += total
	}
}

// printRepoQuotaLimit renders err as a repository storage bar and reports whether err was
// a quota verdict at all. Anything else is a failure to measure the repository, which is
// for the caller to deal with.
func printRepoQuotaLimit(
	output *hook.Output,
	err error,
) bool {
	quotaErr, ok := errors.AsType[*limiter.RepoQuotaStorageError](err)
	if !ok {
		return false
	}

	// A repository has no separate critical threshold, so the hard limit doubles as one.
	appendQuotaMessage(
		output,
		"Repository storage",
		quotaErr.Size,
		quotaErr.SoftLimit,
		quotaErr.HardLimit,
		quotaErr.HardLimit,
		repoQuotaStatus(quotaErr.Level),
	)

	// Only a space for which the hard limit is enforced is rejected. The lower levels,
	// and a crossed hard limit that isn't enforced, are advisory and must not set an error.
	// The bar above already reports the usage against the limit, so the rejection only
	// has to name which limit stopped the push.
	if quotaErr.Level == limiter.RepoQuotaLevelOverLimit {
		output.Error = new(
			criticalColor.Sprint("Repository storage limit exceeded; pushes are blocked."),
		)
	}

	return true
}

// printTotalStorageQuotaLimit renders err as a total storage bar and reports whether err
// was a quota verdict at all, the way printRepoQuotaLimit does.
func printTotalStorageQuotaLimit(
	output *hook.Output,
	err error,
) bool {
	quotaErr, ok := errors.AsType[*limiter.TotalQuotaStorageError](err)
	if !ok {
		return false
	}

	// Total storage thresholds are configured as percentages of the limit rather than as
	// absolute sizes, so they are converted here to the bytes the bar works in.
	appendQuotaMessage(
		output,
		"Total storage",
		quotaErr.Size,
		percentOfLimit(quotaErr.Limit, quotaErr.WarnPercent),
		percentOfLimit(quotaErr.Limit, quotaErr.CriticalPercent),
		quotaErr.Limit,
		totalQuotaStatus(quotaErr.Level),
	)

	if quotaErr.Blocked() {
		output.Error = new(
			criticalColor.Sprint("Total storage limit exceeded; pushes are blocked."),
		)
	}

	return true
}

// percentOfLimit converts a percentage threshold into the byte size it stands for.
// It returns 0 when either side is unset, which appendQuotaMessage reads as "no band".
func percentOfLimit(limit int64, percent int) int64 {
	if limit <= 0 || percent <= 0 {
		return 0
	}
	return limit / 100 * int64(percent)
}

// formatQuotaBytes renders a byte count the way the storage emails and the usage API do,
// so the same figure reads identically on every surface.
func formatQuotaBytes(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	return humanize.IBytes(uint64(bytes)) //nolint:gosec
}

func quotaProgressBar(
	size int64,
	softLimit int64,
	criticalLimit int64,
	hardLimit int64,
) string {
	if hardLimit <= 0 {
		return ""
	}

	const width = 20

	softRatio := float64(softLimit) / float64(hardLimit)
	criticalRatio := float64(criticalLimit) / float64(hardLimit)
	usageRatio := float64(size) / float64(hardLimit)

	softWidth := int(softRatio * width)
	criticalWidth := int(criticalRatio * width)
	usageWidth := int(usageRatio * width)

	if softWidth > width {
		softWidth = width
	}
	if criticalWidth > width {
		criticalWidth = width
	}
	if usageWidth > width {
		usageWidth = width
	}

	// Make sure the boundaries are sane.
	if criticalWidth < softWidth {
		criticalWidth = softWidth
	}

	var bar strings.Builder

	// Used space.
	for i := 0; i < usageWidth; i++ {
		switch {
		case i < softWidth:
			bar.WriteString(infoColor.Sprint("█"))
		case i < criticalWidth:
			bar.WriteString(warningColor.Sprint("█"))
		default:
			bar.WriteString(criticalColor.Sprint("█"))
		}
	}

	// Remaining space.
	for i := usageWidth; i < width; i++ {
		bar.WriteString("░")
	}

	percentage := min(int(usageRatio*100), 100)

	return fmt.Sprintf(
		"[%s] %3d%%  %s / %s",
		bar.String(),
		percentage,
		formatQuotaBytes(size),
		formatQuotaBytes(hardLimit),
	)
}

// quotaStatus is the label shown beside a quota bar. It is derived from the level the
// limiter decided on rather than recomputed from the sizes, because the sizes alone
// cannot tell a usage past the critical threshold from one past the limit itself.
type quotaStatus struct {
	label string
	color *color.Color
}

var (
	quotaStatusOK        = quotaStatus{label: "OK", color: infoColor}
	quotaStatusWarning   = quotaStatus{label: "WARNING", color: warningColor}
	quotaStatusCritical  = quotaStatus{label: "CRITICAL", color: criticalColor}
	quotaStatusOverLimit = quotaStatus{label: "OVER LIMIT", color: criticalColor}
)

func repoQuotaStatus(level limiter.RepoQuotaStorageLevel) quotaStatus {
	switch level {
	case limiter.RepoQuotaLevelSoft:
		return quotaStatusWarning
	// A repository has no critical band, so the hard limit is its last tier. Both levels
	// mean the repository is over it; only the enforced one also rejects the push.
	case limiter.RepoQuotaLevelHard, limiter.RepoQuotaLevelOverLimit:
		return quotaStatusOverLimit
	}
	return quotaStatusOK
}

func totalQuotaStatus(level limiter.TotalQuotaStorageLevel) quotaStatus {
	switch level {
	case limiter.TotalQuotaLevelWarn:
		return quotaStatusWarning
	case limiter.TotalQuotaLevelCritical:
		return quotaStatusCritical
	case limiter.TotalQuotaLevelOverLimit:
		return quotaStatusOverLimit
	}
	return quotaStatusOK
}

func appendQuotaMessage(
	output *hook.Output,
	title string,
	size int64,
	softLimit int64,
	criticalLimit int64,
	hardLimit int64,
	status quotaStatus,
) {
	output.Messages = append(
		output.Messages,
		title,
		fmt.Sprintf(
			"  %s  %s",
			quotaProgressBar(size, softLimit, criticalLimit, hardLimit),
			status.color.Sprint(status.label),
		),
		"",
	)
}

func printCommitterMismatch(
	output *hook.Output,
	commitInfos []git.CommitInfo,
	principalEmail string,
	total int64,
) {
	output.Messages = append(
		output.Messages,
		colorScanHeader.Sprintf(
			"Push contains commits where committer is not the authenticated user (%s):",
			principalEmail,
		),
		"", // add empty line for making it visually more consumable
	)

	for _, info := range commitInfos {
		output.Messages = append(
			output.Messages,
			fmt.Sprintf("  %s    Committer: %s", info.SHA, info.Committer),
			"", // add empty line for making it visually more consumable
		)
	}

	output.Messages = append(
		output.Messages,
		colorScanSummary.Sprintf(
			"%d %s found not matching the authenticated user (%s)",
			total, singularOrPlural("commit", total > 1), principalEmail,
		),
		"", "", // add two empty lines for making it visually more consumable
	)
}

func printLFSPointers(
	output *hook.Output,
	lfsInfos []git.LFSInfo,
	total int64,
) {
	output.Messages = append(
		output.Messages,
		colorScanHeader.Sprintf(
			"Push references unknown LFS objects:",
		),
		"", // add empty line for making it visually more consumable
	)

	for _, info := range lfsInfos {
		output.Messages = append(
			output.Messages,
			fmt.Sprintf(" Object ID: %s", info.ObjID),
			fmt.Sprintf(" File SHA : %s", info.SHA),
			"", // add empty line for making it visually more consumable
		)
	}

	output.Messages = append(
		output.Messages,
		colorScanSummary.Sprintf(
			"%d %s missing",
			total, singularOrPlural("LFS object", total > 1),
		),
		"", "", // add two empty lines for making it visually more consumable
	)
}

func singularOrPlural(noun string, plural bool) string {
	if plural {
		return noun + "s"
	}
	return noun
}
