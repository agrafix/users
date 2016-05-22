{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
module Web.Users.Postgresql () where

import Web.Users.Types

import Control.Monad
#if MIN_VERSION_mtl(2,2,0)
import Control.Monad.Except
#else
import Control.Monad.Error
#endif
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
             CONSTRAINT "l_pk" PRIMARY KEY (lid)
          );
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

#if MIN_VERSION_mtl(2,2,0)
type ErrorT = ExceptT
runErrorT :: ErrorT e m a -> m (Either e a)
runErrorT = runExceptT
#else
-- a hack... :-(
instance Error UpdateUserError where
    noMsg = error "Calling fail not supported"
    strMsg = error "Calling fail not supported"
#endif

getSqlField :: UserField -> BSC.ByteString
getSqlField userField =
    case userField of
      UserFieldId -> "lid"
      UserFieldActive -> "is_active"
      UserFieldEmail -> "email"
      UserFieldName -> "username"
      UserFieldPassword -> "password"

getOrderBy :: SortBy UserField -> BSC.ByteString
getOrderBy sb =
    "ORDER BY " <>
    case sb of
      SortAsc t -> getSqlField t <> " ASC"
      SortDesc t -> getSqlField t <> " DESC"

instance UserStorageBackend Connection where
    type UserId Connection = Int64
    initUserBackend conn =
        do _ <- execute_ conn [sql|CREATE EXTENSION IF NOT EXISTS "uuid-ossp";|]
           _ <- execute_ conn createUsersTable
           _ <- execute_ conn createUserTokenTable
           unlessM (doesIndexExist conn "l_username") $
              do _ <- execute_ conn [sql|CREATE INDEX l_username ON login USING btree(username);|]
                 return ()
           unlessM (doesIndexExist conn "l_email") $
              do _ <- execute_ conn [sql|CREATE INDEX l_email ON login USING btree(email);|]
                 return ()
           unlessM (doesIndexExist conn "l_lower_email") $
              do _ <- execute_ conn [sql|CREATE INDEX l_lower_email ON login USING btree(lower(email));|]
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
    -- | Retrieve a user id from the database
    getUserIdByName conn username =
        listToMaybe <$> map fromOnly <$> query conn [sql|SELECT lid FROM login WHERE (username = ? OR email = ?) LIMIT 1;|] (username, username)
    getUserById conn userId =
        do resultSet <-
               query conn [sql|SELECT username, email, is_active FROM login WHERE lid = ? LIMIT 1;|] (Only userId)
           case resultSet of
             ((username, email, is_active) : _) ->
                 return $ Just $ convertUserTuple (username, PasswordHidden, email, is_active)
             _ -> return Nothing
    listUsers conn mLimit sortField =
        do let limitPart =
                   case mLimit of
                     Nothing -> ""
                     Just (start, count) ->
                         (Query $ BSC.pack $ " OFFSET " ++ show start ++ " LIMIT " ++ show count)
               sortPart =
                   Query $ " " <> getOrderBy sortField <> " "
               baseQuery =
                   [sql|SELECT lid, username, email, is_active FROM login|]
               fullQuery = baseQuery <> sortPart <> limitPart
               convertUser (lid, username, email, isActive) =
                   (lid, convertUserTuple (username, PasswordHidden, email, isActive))
           resultSet <-
               query_ conn fullQuery
           return $ map convertUser resultSet

    countUsers conn =
        do [(Only count)] <-
               query_ conn [sql|SELECT COUNT(lid) FROM login;|]
           return count
    createUser conn user =
        case u_password user of
          PasswordHash p ->
              do ([(Only emailCounter)], [(Only nameCounter)]) <- (,) <$>
                     query conn [sql|SELECT COUNT(lid) FROM login WHERE lower(email) = lower(?) LIMIT 1;|] (Only $ u_email user)
                     <*> query conn [sql|SELECT COUNT(lid) FROM login WHERE username = ? LIMIT 1;|] (Only $ u_name user)
                 let both f (x, y) = (f x, f y)
                     bothCount = both (== 1) (emailCounter :: Int64, nameCounter :: Int64)
                 case bothCount of
                      (True, True)   -> return $ Left UsernameAndEmailAlreadyTaken
                      (True, False)  -> return $ Left EmailAlreadyTaken
                      (False, True)  -> return $ Left UsernameAlreadyTaken
                      (False, False) ->
                        do [(Only userId)] <-
                               query conn [sql|INSERT INTO login (username, password, email, is_active) VALUES (?, ?, ?, ?) RETURNING lid|]
                                     (u_name user, p, u_email user, u_active user)
                           return $ Right userId
          _ ->
              return $ Left InvalidPassword
    updateUser conn userId updateFun =
        do mUser <- getUserById conn userId
           case mUser of
             Nothing ->
                 return $ Left UserDoesntExist
             Just origUser ->
                 runErrorT $
                 do let newUser = updateFun origUser
                    when (u_name newUser /= u_name origUser) $
                         do [(Only counter)] <-
                                liftIO $ query conn [sql|SELECT COUNT(lid) FROM login WHERE username = ?;|] (Only $ u_name newUser)
                            when ((counter :: Int64) /= 0) $ throwError UsernameAlreadyExists
                    when (u_email newUser /= u_email origUser) $
                         do [(Only counter)] <-
                                liftIO $ query conn [sql|SELECT COUNT(lid) FROM login WHERE lower(email) = lower(?);|] (Only $ u_email newUser)
                            when ((counter :: Int64) /= 0) $ throwError EmailAlreadyExists
                    liftIO $
                       do _ <-
                              execute conn [sql|UPDATE login SET username = ?, email = ?, is_active = ? WHERE lid = ?;|]
                                 (u_name newUser, u_email newUser, u_active newUser, userId)
                          case u_password newUser of
                            PasswordHash p ->
                                do _ <-
                                      execute conn [sql|UPDATE login SET password = ? WHERE lid = ?;|] (p, userId)
                                   return ()
                            _ -> return ()
                          return ()
    deleteUser conn userId =
        do _ <- execute conn [sql|DELETE FROM login WHERE lid = ?;|] (Only userId)
           return ()
    authUser conn username password sessionTtl =
        withAuthUser conn username (\user -> verifyPassword password $ u_password user) $ \userId ->
           SessionId <$> createToken conn "session" userId sessionTtl
    createSession conn userId sessionTtl =
        do mUser <- getUserById conn userId
           case (mUser :: Maybe User) of
             Nothing -> return Nothing
             Just _ -> Just . SessionId <$> createToken conn "session" userId sessionTtl
    withAuthUser conn username authFn action =
        do resultSet <- query conn [sql|SELECT lid, username, password, email, is_active FROM login WHERE (username = ? OR email = ?) LIMIT 1;|] (username, username)
           case resultSet of
             ((userId, name, password, email, is_active) : _)
               -> do let user = convertUserTuple (name, PasswordHash password, email, is_active)
                     if authFn user
                        then Just <$> action userId
                        else return Nothing
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
                        updateUser conn userId $ \user -> user { u_active = True }
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
                        updateUser conn userId $ \user -> user { u_password = password }
                    deleteToken conn "password_reset" token
                    return $ Right ()

convertTtl :: NominalDiffTime -> Int
convertTtl = round

createToken :: Connection -> String -> Int64 -> NominalDiffTime -> IO T.Text
createToken conn tokenType userId timeToLive =
    do [Only sessionToken] <-
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
                  execute conn [sql|
                                   UPDATE login_token
                                   SET valid_until =
                                            (CASE WHEN NOW() + '? seconds' > valid_until THEN NOW() + '? seconds' ELSE valid_until END)
                                   WHERE token_type = ?
                                   AND token = ?;|] (convertTtl timeToLive, convertTtl timeToLive, tokenType, uuid)
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

convertUserTuple :: (T.Text, Password, T.Text, Bool) -> User
convertUserTuple (username, password, email, isActive) =
    User username email password isActive
