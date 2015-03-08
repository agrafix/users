#/usr/bin/env/sh
set -e

PKG="$1"

cd $PKG
cabal sandbox init

case "$PKG" in
    users-test)
        cabal sandbox add-source ../users
        ;;
    users-postgresql-simple)
        cabal sandbox add-source ../users
        cabal sandbox add-source ../users-test
        ;;
    *)
        echo "No sandbox sources to add!"
        ;;
esac

cabal install -j8 --only-dep --enable-tests
cabal configure --enable-tests
cabal build
