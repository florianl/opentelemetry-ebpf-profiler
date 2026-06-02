package interpreter

// ID represents the identity for an interpreter.
type ID string

const (
	PythonID  ID = "python"
	PHPID     ID = "php"
	HotspotID ID = "hotspot"
	RubyID    ID = "ruby"
	V8ID      ID = "v8"
	DotnetID  ID = "dotnet"
	BEAMID    ID = "beam"
	PerlID    ID = "perl"
	LabelsID  ID = "labels"
	GoID      ID = "go"
)

