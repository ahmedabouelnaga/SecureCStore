#include "hmac_args.h"

// modeled after GNU example 3:
// https://www.gnu.org/software/libc/manual/html_node/Argp-Example-3.html
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
        arguments args2;
        arguments *args = (arguments *) state->input;
        switch(key)
        {
                case 'p':
                        if (arg != NULL)
                                args->password = arg;
                        break;
                case 'o':
                        if (arg != NULL)
                                args->outfile = arg;
                        break;
                case 'v':
                        if (arg != NULL) {
                                args->verify_hash = arg;
                                args->mode = "verify";
                        }
                        break;
                case ARGP_KEY_ARG: // source_file
                        if(state->arg_num > 0) {
                                argp_usage(state);
                        }
                        args->source_file = arg;
                        break;
                case ARGP_KEY_END:
                        if(state->arg_num < 1) {
                                argp_usage(state);
                        }
                        break;
                default:
                      return ARGP_ERR_UNKNOWN;
        }
        return 0;
}


/**
 * @brief parse command line arguments into variables
 * 
 * @param argc - program argc for parsing
 * @param argv - program argv for parsing
 */
HMACArgs::HMACArgs(int argc, char ** argv)
{
        // a bit of a wrapper for argparse:
        // https://www.gnu.org/software/libc/manual/html_node/Argp.html
        
        static char doc[] =
        "Make an HMAC of the file stored at source_file";

        static char args_doc[] = "source_file";

        static struct argp_option options[] = {
                {
                        "password",  // name
                        'p',         // key
                        "password",           // arg
                        0, //flags
                        "The password to use; will prompt if not given" // string documentation
                },
                {
                        "verify",  // name
                        'v',         // key
                        "hash",           // arg
                        0, //flags
                        "Verify an existing hash, provided as a hex-encoded ascii string" // string documentation
                },
                {"outfile", 'o', "filename", 
                        0,  "File to write hmac to as binary;"
                        " otherwise prints to stdout as hex" },
                { 0 }
        };
        args.mode = "create";
        static struct argp argp = { options, parse_opt, args_doc, doc };
        argp_parse (&argp, argc, argv, 0, 0, &args);

        if (args.password == "") {
                char * temp_password = getpass("\tPlease enter a password to use: ");
                args.password = temp_password;
                free(temp_password);
        }

        if (args.outfile == "") {
                args.outfile = "STDOUT";
        }
}

std::string HMACArgs::get_password()
{
        return args.password;
}

std::string HMACArgs::get_outfile()
{
        return args.outfile;
}

std::string HMACArgs::get_sourcefile()
{
        return args.source_file;
}

std::string HMACArgs::get_mode()
{
        return args.mode;
}

std::string HMACArgs::get_verify_hash()
{
        return args.verify_hash;
}