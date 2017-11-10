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
   --pubring value, --pub value    GNUPG public keyring (default: "~/.gnupg/pubring.gpg")
   --secring value, --sec value    GNUPG private keyring (default: "~/.gnupg/secring.gpg")
   --secure_name value, -n value   secure variable name
   --secrets_file value, -f value  path to a file to be encrypted (a file name of '-' will read from STDIN) (default: "/dev/stdin")
   --output_file value, -o value   path to a file to be written (defaults to STDOUT) (default: "/dev/stdout")
   --secret value, -s value        secret string value to be encrypted
   --gpg_key value, -k value       GPG key name, email, or ID to use for encryption
   --encrypt_all, -a               encrypt all non-encrypted values in a file
   --recurse value, -r value       recurse over all .sls files in the given path (implies --encrypt_all)
   --debug                         adds line number info to log output
   --help, -h                      show help
   --version, -v                   print the version

EXAMPLES:
    # create a new sls file
    $ ./generate-secure-pillar -k "Salt Master" -n secret_name -s secret_value -o new.sls
    # add to the new file
    $ ./generate-secure-pillar -k "Salt Master" -n secret_name2 -s secret_value2 -f new.sls -o new.sls
    # update an existing value
    $ ./generate-secure-pillar -k "Salt Master" -n secret_name2 -s secret_value3 -f new.sls -o new.sls
    # encrypt all plain text values in a file
    $ ./generate-secure-pillar -k "Salt Master" -a -f us1.sls -o us1.sls
    # recurse through all sls files, creating new encrypted files with a .new extension
    $ ./generate-secure-pillar -k "Salt Master" -r ~/Desktop/src/atlas-salt-pillar/

COPYRIGHT:
   (c) 2017 Everbridge, Inc.
