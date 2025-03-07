package dpkg

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_dpkgLicenseAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		testFile string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "machine-readable format",
			filePath: "usr/share/doc/zlib1g/copyright",
			testFile: "testdata/license-pattern-and-classifier-copyright",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeDpkg,
						FilePath: "usr/share/doc/zlib1g/copyright",
						Findings: []types.LicenseFinding{
							{Name: "GPL-1.0-or-later"},
							{Name: "Artistic-2.0"},
							{Name: "BSD-4-clause-POWERDOG"},
							{Name: "Zlib"},
						},
						PkgName: "zlib1g",
					},
				},
			},
		},
		{
			name:     "common-licenses format",
			filePath: "usr/share/doc/adduser/copyright",
			testFile: "testdata/common-license-copyright",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeDpkg,
						FilePath: "usr/share/doc/adduser/copyright",
						Findings: []types.LicenseFinding{
							{Name: "GPL-2.0-only"},
						},
						PkgName: "adduser",
					},
				},
			},
		},
		{
			name:     "machine-readable and common-licenses format",
			filePath: "usr/share/doc/apt/copyright",
			testFile: "testdata/all-patterns-copyright",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeDpkg,
						FilePath: "usr/share/doc/apt/copyright",
						Findings: []types.LicenseFinding{
							{Name: "GPL-2.0-or-later"},
							{Name: "GPL-2.0-only"},
						},
						PkgName: "apt",
					},
				},
			},
		},
		{
			name:     "no license found",
			filePath: "usr/share/doc/tzdata/copyright",
			testFile: "testdata/no-license-copyright",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			f, err := os.Open(tt.testFile)
			r.NoError(err)

			input := analyzer.AnalysisInput{
				Content:  f,
				FilePath: tt.filePath,
			}
			a := dpkgLicenseAnalyzer{}

			license, err := a.Analyze(context.Background(), input)
			r.NoError(err)
			r.Equal(tt.want, license)
		})
	}
}

func Test_dpkgLicenseAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "usr/share/doc/eject/copyright",
			want:     true,
		},
		{
			name:     "bad prefix",
			filePath: "usr/share/doc/eject/copyright/file",
			want:     false,
		},
		{
			name:     "bad file name",
			filePath: "usr/share/doc/eject/copyright/foo",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			a := dpkgLicenseAnalyzer{}
			r.Equal(tt.want, a.Required(tt.filePath, nil))
		})
	}
}
