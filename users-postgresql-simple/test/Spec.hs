{-# LANGUAGE OverloadedStrings #-}
module Main where

import Web.Users.TestSpec
import Web.Users.Postgresql ()

import Database.PostgreSQL.Simple
import Test.Hspec

main :: IO ()
main =
    do conn <- connectPostgreSQL ""
       hspec $ makeUsersSpec conn
