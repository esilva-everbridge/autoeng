NAME:
   generate-secure-pillar - add or update secure salt pillar content

USAGE:
   generate-secure-pillar [global options] command [command options] [arguments...]

VERSION:
   0.1

AUTHOR:
   Ed Silva <ed.silva@everbridge.com>

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --token value, -t value         github API token [$GITHUB_TOKEN]
   --pubring value, --pub value    GNUPG public keyring (default: "~/.gnupg/pubring.gpg")
   --secring value, --sec value    private keyring (default: "~/.gnupg/secring.gpg")
   --github_org value, -o value    github organization (default: "Everbridge")
   --pillar_name value, -p value   secure pillar name (default: "atlas-salt-pillar")
   --secret_name value, -s value   secret name
   --github_repo value, -r value   github repo name
   --secrets_file value, -f value  path to a yaml file to be encrypted
   --gpg_key value, -k value       GPG key name to use for encryption
   --help, -h                      show help
   --version, -v                   print the version

COPYRIGHT:
   (c) 2017 Everbridge, Inc.
