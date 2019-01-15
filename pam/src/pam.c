#include <security/pam_appl.h>
#include <sys/resource.h>
#include <string.h>
#include <stdlib.h>

struct creds {
    char *user;
    char *password;
};

static void add_reply(struct pam_response **reply, int count, char *txt)
{
    *reply = realloc(*reply, (count + 1) * sizeof(struct pam_response));
    (*reply)[count].resp_retcode = 0;
    (*reply)[count].resp = strdup(txt ? txt: "");
}

static int c_pam_conv(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata)
{
    struct pam_response *reply = NULL;
    struct creds *creds = (struct creds *)appdata;
    int replies = 0;

    int count;
    for (count = 0; count < num_msg; count++) {
        switch (msg[count]->msg_style) {
            case PAM_PROMPT_ECHO_ON:
                add_reply(&reply, replies++, creds->user);
                break;
            case PAM_PROMPT_ECHO_OFF:
                add_reply(&reply, replies++, creds->password);
                break;
            case PAM_TEXT_INFO:
                break;
            case PAM_ERROR_MSG:
            default:
                if (reply != NULL)
                    free(reply);
                return PAM_CONV_ERR;
      }
    }
    *resp = reply;
    return PAM_SUCCESS;
}

int c_pam_auth(char *service, char *user, char *pass, char *remip)
{
    struct creds creds = {
        user,
        pass,
    };
    struct pam_conv conv = {
        c_pam_conv,
        &creds,
    };

    pam_handle_t *pamh = NULL;
    int ret = pam_start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS)
            return ret;
    if (ret == PAM_SUCCESS && remip && remip[0])
        ret = pam_set_item(pamh, PAM_RHOST, remip);
    if (ret == PAM_SUCCESS)
        ret = pam_authenticate(pamh, 0);
    pam_end(pamh, 0);

    return ret;
}

void c_pam_lower_rlimits()
{
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim_t l = rlim.rlim_cur;
        if (l > 256)
            l = 256;
        rlim.rlim_cur = l;
        rlim.rlim_max = l;
        setrlimit(RLIMIT_NOFILE, &rlim);
    }
}
