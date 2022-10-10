{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies  #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DataKinds #-}

module Web.Users.Persistent.Definitions where

import Database.Persist.TH
import Data.Time.Clock
import Data.Typeable
import qualified Data.Text as T

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
Login
    createdAt UTCTime
    username T.Text
    email T.Text
    password T.Text
    active Bool
    UniqueUsername username
    UniqueEmail email
    deriving Show
    deriving Eq
    deriving Typeable
LoginToken
    token T.Text
    tokenType T.Text
    createdAt UTCTime
    validUntil UTCTime
    owner LoginId
    UniqueToken token
    UniqueTypedToken token tokenType
    deriving Show
    deriving Eq
    deriving Typeable
|]
