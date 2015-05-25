{-# LANGUAGE OverloadedStrings #-}
module Main where

import Web.Users.TestSpec
import Web.Users.Persistent

import System.IO.Temp
import System.IO
import Control.Monad.Logger
import Database.Persist.Sqlite
import Test.Hspec
import qualified Data.Text as T

main :: IO ()
main =
    withSystemTempFile "tempBaseXXX.db" $ \fp hdl ->
    do hClose hdl
       pool <- runNoLoggingT $ createSqlitePool (T.pack fp) 5
       hspec $ makeUsersSpec (Persistent $ flip runSqlPool pool)
