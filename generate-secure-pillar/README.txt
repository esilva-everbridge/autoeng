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
   --secring value, --sec value    GNUPG private keyring (default: "~/.gnupg/secring.gpg")
   --github_org value, -o value    github organization (default: "Everbridge")
   --secret_name value, -s value   secret name
   --secrets_file value, -f value  path to a file to be encrypted (a file name of '-' will read from STDIN)
   --output_file value             path to a file to be written (defaults to STDOUT)
   --update, -u                    update the output file only (can't be stdout, will not overwrite existing files)
   --secret value                  secret string to be encrypted
   --gpg_key value, -k value       GPG key name to use for encryption
   --help, -h                      show help
   --version, -v                   print the version


EXAMPLES:
    # create a new sls file
    $ ./generate-secure-pillar -k "Salt Master" -s foo --secret bar -f - > new.sls
    # add to the new file
    $ ./generate-secure-pillar -k "Salt Master" -s bar --secret baz -f new.sls

COPYRIGHT:
   (c) 2017 Everbridge, Inc.
