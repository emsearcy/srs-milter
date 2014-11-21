SRS milter plugin for postfix
=============================

This milter implemets SRS (Sender Rewriting Scheme) that can be used to fix envelope MAIL FROM for forwarded mails protected by SPF. It can be configured in two modes for:

* Incoming mail -- rewrite RCPT TO addresses in SRS format back
* Outgoing mail -- rewrite MAIL FROM address to SRS format


Download
--------

The original source of srs-milter can be found here: http://kmlinux.fjfi.cvut.cz/~vokacpet/activities/srs-milter/

It has been updated and tweaked by emsearcy and Driskell and distributed via GitHub.


Dependencies
------------

* postfix 2.5 -- supports SMFIF_CHGFROM
* libmilter -- compatible with sendmail 8.14.0 and higher
* libspf2 -- to be able to rewrite only outgoing addresses that can be rejected by SPF checks on final MTA
* libsrs2 -- for SRS address rewriting

Both libraries contain several patches that are not part of official source code but comes from different distributions (debian, freebsd).


Configuration
-------------

Incomming mail:

* Start srs-milter in reverse mode
  ```
  srs-filter --socket=inet:10044@localhost --reverse \
      --local-domain=example.com --local-domain=.allsubdomain.example.com \
      --srs-domain=srs.example.com --srs-secret-file=/etc/srs-secrets \
      -P /var/run/srs-filter1.pid
  ```

* Configure Postfix to use the milter in main.cf
  ```
  smtpd_milters = inet:localhost:10044
  ```

* NOTE: You should also add new hash entry to your `local_recipient_maps` directive to ensure Postfix treats SRS address as valid addresses. Without this, SRS addresses will never reach srs-milter for decoding because Postfix will immediately reject the address as non-existent. Your new directive might look something like this (this is actually the Postfix default with the new hash added):
  ```
  local_recipient_maps = proxy:unix:passwd.byname $alias_maps hash:/etc/postfix/srsdomain
  ```
  And `/etc/postfix/srsdomain` would contain your full SRS domain - the second value after the entry is ignored for `local_recipient_maps` so a hyphen is fine:
  ```
  @srsdomain.com -
  ```

Outgoing mail:

* Start srs-milter in forward mode
  ```
  srs-filter --socket=inet:10043@localhost --forward \
      --local-domain=example.com --local-domain=.allsubdomain.example.com \
      --srs-domain=srs.example.com --srs-secret-file=/etc/srs-secrets \
      --spf-check \
      -P /var/run/srs-filter0.pid
  ```

* Configure Postfix to use the milter in main.cf
  ```
  smtpd_milters = inet:localhost:10044
  ```

* NOTE: If you use virtual_alias_maps for outgoing mails to change recipient address you can't use same smtpd with srs-milter (it doesn't see changes from rewriting virtual aliases). In main.cf you can define new smtpd that listens on different port and forward all outgoing mails throught this smtpd configured with srs-milter.

Other notes
-----------

From http://kmlinux.fjfi.cvut.cz/~vokacpet/:
I use this milter on low traffic site (~ 30k mails a day) without problems (currently ~ 500k mails in reverse mode and ~ 50k mails in forward mode). But still it is basically quick hack for my current needs and the code is far from being nice and clean.
