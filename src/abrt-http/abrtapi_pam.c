

static int PAM_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
  int replies = 0;
  struct pam_response *reply = NULL;

  reply = malloc(sizeof(struct pam_response)*num_msg);
  if (!reply)
    return PAM_CONV_ERR;
  #define COPY_STRING(s) (s) ? strdup(s) : NULL
  fprintf(stderr, "start:\n");
  for (replies = 0; replies < num_msg; replies++)
    {
      switch (msg[replies]->msg_style)
        {
    case PAM_PROMPT_ECHO_OFF:
      /* wants password */
      reply[replies].resp_retcode = PAM_SUCCESS;
      reply[replies].resp = appdata_ptr ? strdup((char *)appdata_ptr) : 0;
      break;
    case PAM_TEXT_INFO:
      /* ignore the informational mesage */
      /* but first clear out any drek left by malloc */
      reply[replies].resp = NULL;
      break;
    case PAM_PROMPT_ECHO_ON:
      /* user name given to PAM already */
      /* fall through */
    default:
      /* unknown or PAM_ERROR_MSG */
      free(reply);
      return PAM_CONV_ERR;
    }
    }
  *resp = reply;
  
  return PAM_SUCCESS;
}