#include "aes_args.h"

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
                case ARGP_KEY_ARG: // source_file
                        if(state->arg_num > 1) {
                                argp_usage(state);
                        }
                        if( (args->mode == MODE_ENCRYPT && 
                        state->arg_num == 0) || 
                        (args->mode == MODE_DECRYPT && 
                        state->arg_num == 1)){
                                args->plaintext_file = arg;
                        } else {
                                args->encrypted_file = arg;
                        }
                        
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
AESArgs::AESArgs(int argc, char ** argv, unsigned short mode)
{
        // a bit of a wrapper for argparse:
        // https://www.gnu.org/software/libc/manual/html_node/Argp.html
        
        static char doc_encrypt[] =
        "Encrypt a file using AES-CBC";
        static char doc_decrypt[] =
        "Decrypt a file using AES-CBC";

        static char args_doc_encrypt[] = "plaintext_in encrypted_out";
        static char args_doc_decrypt[] = "encrypted_in plaintext_out";

        static char * args_doc;
        static char * doc;

        if(mode == MODE_ENCRYPT) {
                args_doc = args_doc_encrypt;
                doc = doc_encrypt;
        } else {
                args_doc = args_doc_decrypt;
                doc = doc_decrypt;
        }

        args.mode = mode;

        static struct argp_option options[] = {
                {
                        "password",  // name
                        'p',         // key
                        "password",           // arg
                        0, //flags
                        "The password to use; will prompt if not given" // string documentation
                },
                { 0 }
        };
        static struct argp argp = { options, parse_opt, args_doc, doc };
        argp_parse (&argp, argc, argv, 0, 0, &args);

        if (args.password == "") {
                char * temp_password = getpass("\tPlease enter a password to use: ");
                args.password = temp_password;
                free(temp_password);
        }
}

std::string AESArgs::get_password()
{
        return args.password;
}

unsigned short AESArgs::get_mode()
{
        return args.mode;
}

std::string AESArgs::get_plaintext_file()
{
        return args.plaintext_file;
}

std::string AESArgs::get_encrypted_file()
{
        return args.encrypted_file;
}