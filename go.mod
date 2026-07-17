module crypt

go 1.25.6

require (
	github.com/1101947/cliargumentrouter v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.41.0
	golang.org/x/term v0.34.0
)

replace github.com/1101947/cliargumentrouter => ../go_cliargumentrouter

require golang.org/x/sys v0.35.0 // indirect
