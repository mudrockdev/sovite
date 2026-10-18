# Sourced by the commands of the Sovite package (sovite, sovitectl,
# sendmail, mailq, newaliases) before they run the single binary.
#
# The binary runs from the copy the package unpacked in /usr/lib/sovite
# (at install time, as root), instead of unpacking itself into each
# user's home. Its Erlang runtime needs the musl C library at a fixed
# path in /tmp, which systemd-tmpfiles creates at boot (sovite-runtime.conf).
# A copy there that another user could have planted or can change would
# run as whoever runs a command, so it must belong to root or to this
# user, be writable by nobody else, and be the packaged one.

# Unpacked in $XDG_DATA_HOME/.burrito. (SOVITE_INSTALL_DIR would do the
# same, but makes the binary print a notice on standard output.)
XDG_DATA_HOME=/usr/lib/sovite
export XDG_DATA_HOME

sovite_runtime=/tmp/@MUSL_NAME@

if [ ! -e "$sovite_runtime" ] && [ ! -L "$sovite_runtime" ]; then
  # Not there (a private /tmp, or tmpfiles has not run): this user's own.
  cp /usr/lib/sovite/libc-musl.so "$sovite_runtime" 2>/dev/null || true
  chmod 0755 "$sovite_runtime" 2>/dev/null || true
fi

sovite_refuse() {
  echo "sovite: refusing to run: $sovite_runtime $1" >&2
  exit 70
}

[ -L "$sovite_runtime" ] && sovite_refuse "is a symbolic link"
[ -f "$sovite_runtime" ] || sovite_refuse "is missing or not a regular file"

sovite_owner=$(stat -c %u "$sovite_runtime")
if [ "$sovite_owner" != 0 ] && [ "$sovite_owner" != "$(id -u)" ]; then
  sovite_refuse "belongs to another user"
fi

case $(stat -c %A "$sovite_runtime") in
  ?????w????|????????w?) sovite_refuse "is writable by other users" ;;
esac

if [ "$(sha256sum "$sovite_runtime" | cut -d ' ' -f 1)" != "@MUSL_SHA256@" ]; then
  sovite_refuse "is not the packaged musl runtime"
fi

unset sovite_runtime sovite_owner
