Walden hard-blocks distracting websites for a fixed period.

WHAT THIS INSTALLS

  /usr/local/bin/walden                          the command you run
  /usr/local/bin/walden-uninstall                removes everything above
  /usr/local/libexec/waldend                     the privileged daemon
  /Library/LaunchDaemons/org.scotto.waldend.plist  its launchd job
  /usr/local/share/walden/catalog/v1/            website category lists
  /usr/local/share/doc/walden/                   documentation and license

NOTHING RUNS UNTIL YOU START A BLOCK

  The daemon is installed inactive. Installing Walden does not block anything
  and does not start a background process. Running

      walden start --unlock-delay "3 days"

  is what starts the daemon, and it stops again when the block ends.

A BLOCK IS NOT MEANT TO BE EASY TO UNDO

  Once a block starts, the websites stay blocked until the unlock delay you
  chose has passed. The wait cannot be shortened or cancelled. Quitting the
  command, logging out, restarting the machine, and uninstalling Walden all
  leave the block in place.

REMOVING WALDEN

      sudo walden-uninstall

  This stops the daemon and removes every file listed above. It refuses to run
  while a block is active, because removing Walden does not lift a block: the
  hosts entries and firewall rules stay, and nothing is left to remove them
  when the block ends.

  The daemon's persisted block state is kept, so an unfinished block resumes if
  Walden is installed again. `sudo walden-uninstall --purge` deletes it.

REQUIREMENTS

  Administrator rights. The daemon edits /etc/hosts and the packet filter, and
  runs as root under launchd.
