{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Web.Users.Postgresql () where

import Web.Users.Types

import Control.Monad
import Control.Monad.Except
import Data.Aeson
import Data.Int
import Data.Maybe
import Data.Monoid
import Data.Time.Clock
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.SqlQQ
import Database.PostgreSQL.Simple.Types
import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text as T
import qualified Data.UUID as UUID

createUsersTable :: Query
createUsersTable =
    [sql|
          CREATE TABLE IF NOT EXISTS login (
             lid             SERIAL UNIQUE,
             created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_DATE,
             username        VARCHAR(64)    NOT NULL UNIQUE,
             password        VARCHAR(255)   NOT NULL,
             email           VARCHAR(64)   NOT NULL UNIQUE,
             is_active       BOOLEAN NOT NULL DEFAULT FALSE,
             more            JSON,
          CONSTRAINT "l_pk" PRIMARY KEY (lid));
    |]

createUserTokenTable :: Query
createUserTokenTable =
    [sql|
          CREATE TABLE IF NOT EXISTS login_token (
             ltid             SERIAL UNIQUE,
             token            UUID UNIQUE,
             token_type       VARCHAR(64) NOT NULL,
             lid              INTEGER NOT NULL,
             created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_DATE,
             valid_until      TIMESTAMPTZ NOT NULL,
             CONSTRAINT "lt_pk" PRIMARY KEY (ltid),
             CONSTRAINT "lt_lid_fk" FOREIGN KEY (lid) REFERENCES login ON DELETE CASCADE
          );
    |]

doesIndexExist :: Connection -> String -> IO Bool
doesIndexExist conn idx =
    do (resultSet :: [Only Int]) <-
           query conn [sql|SELECT 1
                            FROM pg_class c
                            JOIN pg_namespace n ON n.oid = c.relnamespace
                            WHERE c.relname = ?
                            AND n.nspname = 'public';
                      |] (Only idx)
       return (length resultSet > 0)

unlessM :: Monad m => m Bool -> m () -> m ()
unlessM check a =
    do r <- check
       unless r a

instance UserStorageBackend Connection where
    type UserId Connection = Int64
    initUserBackend conn =
        do _ <- execute_ conn [sql|CREATE EXTENSION IF NOT EXISTS pgcrypto;|]
           _ <- execute_ conn [sql|CREATE EXTENSION IF NOT EXISTS "uuid-ossp";|]
           _ <- execute_ conn createUsersTable
           _ <- execute_ conn createUserTokenTable
           unlessM (doesIndexExist conn "l_username") $
              do _ <- execute_ conn [sql|CREATE INDEX l_username ON login USING btree(username);|]
                 return ()
           unlessM (doesIndexExist conn "l_email") $
              do _ <- execute_ conn [sql|CREATE INDEX l_email ON login USING btree(email);|]
                 return ()
           unlessM (doesIndexExist conn "lt_token_type") $
              do _ <- execute_ conn [sql|CREATE INDEX lt_token_type ON login_token USING btree(token_type);|]
                 return ()
           unlessM (doesIndexExist conn "lt_token") $
              do _ <- execute_ conn [sql|CREATE INDEX lt_token ON login_token USING btree(token);|]
                 return ()
           return ()
    destroyUserBackend conn =
        do _ <- execute_ conn [sql|DROP TABLE login_token;|]
           _ <- execute_ conn [sql|DROP TABLE login;|]
           return ()
    housekeepBackend conn =
        do _ <- execute_ conn [sql|DELETE FROM login_token WHERE valid_until < NOW();|]
           return ()
    getUserById conn userId =
        do resultSet <-
               query conn [sql|SELECT username, email, is_active, more FROM login WHERE lid = ? LIMIT 1;|] (Only userId)
           case resultSet of
             (userTuple : _) ->
                 return $ convertUserTuple userTuple
             _ -> return Nothing
    listUsers conn mLimit =
        do let limitPart =
                   case mLimit of
                     Nothing -> ""
                     Just (start, count) ->
                         (Query $ BSC.pack $ " LIMIT " ++ show start ++ ", " ++ show count)
               baseQuery =
                   [sql|SELECT lid, username, email, is_active, more FROM login|]
               fullQuery = baseQuery <> limitPart
               convertUser (lid, username, email, isActive, more) =
                   do user <- convertUserTuple (username, email, isActive, more)
                      return (lid, user)
           resultSet <-
               query_ conn fullQuery
           return $ catMaybes $ map convertUser resultSet

    countUsers conn =
        do [(Only count)] <-
               query_ conn [sql|SELECT COUNT(lid) FROM login;|]
           return count
    createUser conn user =
        case u_password user of
          PasswordPlain p ->
              do [(Only counter)] <-
                     query conn [sql|SELECT COUNT(lid) FROM login WHERE username = ? OR email = ?;|] (u_name user, u_email user)
                 if (counter :: Int64) /= 0
                 then return $ Left UsernameOrEmailAlreadyTaken
                 else do [(Only userId)] <-
                             query conn [sql|INSERT INTO login (username, password, email, is_active, more) VALUES (?, crypt(?, gen_salt('bf', 8)), ?, ?, ?) RETURNING lid|]
                                   (u_name user, p, u_email user, u_active user, toJSON $ u_more user)
                         return $ Right userId
          _ ->
              return $ Left InvalidPassword
    updateUser conn userId updateFun =
        do mUser <- getUserById conn userId
           case mUser of
             Nothing ->
                 return $ Left UserDoesntExit
             Just origUser ->
                 runExceptT $
                 do let newUser = updateFun origUser
                    when (u_name newUser /= u_name origUser) $
                         do [(Only counter)] <-
                                liftIO $ query conn [sql|SELECT COUNT(lid) FROM login WHERE username = ?;|] (Only $ u_name newUser)
                            when ((counter :: Int64) /= 0) $ throwError UsernameOrEmailAlreadyExists
                    when (u_email newUser /= u_email origUser) $
                         do [(Only counter)] <-
                                liftIO $ query conn [sql|SELECT COUNT(lid) FROM login WHERE email = ?;|] (Only $ u_email newUser)
                            when ((counter :: Int64) /= 0) $ throwError UsernameOrEmailAlreadyExists
                    liftIO $
                       do _ <-
                              execute conn [sql|UPDATE login SET username = ?, email = ?, is_active = ?, more = ? WHERE lid = ?;|]
                                 (u_name newUser, u_email newUser, u_active newUser, toJSON $ u_more newUser, userId)
                          case u_password newUser of
                            PasswordPlain p ->
                                do _ <-
                                      execute conn [sql|UPDATE login SET password = crypt(?, gen_salt('bf', 8)) WHERE lid = ?;|] (p, userId)
                                   return ()
                            _ -> return ()
                          return ()
    deleteUser conn userId =
        do _ <- execute conn [sql|DELETE FROM login WHERE lid = ?;|] (Only userId)
           return ()
    authUser conn username password sessionTtl =
        do resultSet <-
               query conn [sql|SELECT lid FROM login WHERE (username = ? OR email = ?) AND crypt(?, password) = password LIMIT 1;|] (username, username, password)
           case resultSet of
             ((Only userId) : _) ->
                 do sessionToken <- createToken conn "session" userId sessionTtl
                    return $ Just $ SessionId sessionToken
             _ -> return Nothing
    verifySession conn (SessionId sessionId) extendTime =
        do mUser <- getTokenOwner conn "session" sessionId
           case mUser of
             Nothing -> return Nothing
             Just userId ->
                 do extendToken conn "session" sessionId extendTime
                    return (Just userId)
    destroySession conn (SessionId sessionId) = deleteToken conn "session" sessionId
    requestPasswordReset conn userId timeToLive =
        do token <- createToken conn "password_reset" userId timeToLive
           return $ PasswordResetToken token
    requestActivationToken conn userId timeToLive =
        do token <- createToken conn "activation" userId timeToLive
           return $ ActivationToken token
    activateUser conn (ActivationToken token) =
        do mUser <- getTokenOwner conn "activation" token
           case mUser of
             Nothing ->
                 return $ Left TokenInvalid
             Just userId ->
                 do _ <-
                        updateUser conn userId $ \(user :: User Value) -> user { u_active = True }
                    deleteToken conn "activation" token
                    return $ Right ()
    verifyPasswordResetToken conn (PasswordResetToken token) =
        do mUser <- getTokenOwner conn "password_reset" token
           case mUser of
             Nothing -> return Nothing
             Just userId -> getUserById conn userId
    applyNewPassword conn (PasswordResetToken token) password =
        do mUser <- getTokenOwner conn "password_reset" token
           case mUser of
             Nothing ->
                 return $ Left TokenInvalid
             Just userId ->
                 do _ <-
                        updateUser conn userId $ \(user :: User Value) -> user { u_password = PasswordPlain password }
                    deleteToken conn "password_reset" token
                    return $ Right ()

convertTtl :: NominalDiffTime -> Int
convertTtl = round

createToken :: Connection -> String -> Int64 -> NominalDiffTime -> IO T.Text
createToken conn tokenType userId timeToLive =
    do [(Only sessionToken)] <-
           query conn [sql|INSERT INTO login_token (token, token_type, lid, valid_until)
                            VALUES (uuid_generate_v4(), ?, ?, NOW() + '? seconds')
                                   RETURNING token;|]
                     (tokenType, userId :: Int64, convertTtl timeToLive)
       return (T.pack $ UUID.toString sessionToken)

deleteToken :: Connection -> String -> T.Text -> IO ()
deleteToken conn tokenType token =
    case UUID.fromString (T.unpack token) of
      Nothing -> return ()
      Just uuid ->
          do _ <- execute conn [sql|DELETE FROM login_token WHERE token_type = ? AND token = ?;|] (tokenType, uuid)
             return ()

extendToken :: Connection -> String -> T.Text -> NominalDiffTime -> IO ()
extendToken conn tokenType token timeToLive =
    case UUID.fromString (T.unpack token) of
      Nothing -> return ()
      Just uuid ->
          do _ <-
                  execute conn [sql|UPDATE login_token SET valid_until = valid_until + '? seconds' WHERE token_type = ? AND token = ?;|] (convertTtl timeToLive, tokenType, uuid)
             return ()

getTokenOwner :: Connection -> String -> T.Text -> IO (Maybe Int64)
getTokenOwner conn tokenType token =
    case UUID.fromString (T.unpack token) of
      Nothing -> return Nothing
      Just uuid ->
          do resultSet <- query conn [sql|SELECT lid FROM login_token WHERE token_type = ? AND token = ? AND valid_until > NOW() LIMIT 1;|] (tokenType, uuid)
             case resultSet of
               ((Only userId) : _) -> return $ Just userId
               _ -> return Nothing

convertUserTuple :: (FromJSON a, Monad m) => (T.Text, T.Text, Bool, Value) -> m (User a)
convertUserTuple (username, email, isActive, more) =
    case fromJSON more of
      Error e -> fail e
      Success val ->
          return $ User username email PasswordHidden isActive val
