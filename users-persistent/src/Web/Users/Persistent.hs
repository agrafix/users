{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies  #-}
module Web.Users.Persistent (LoginId, Persistent(..)) where

import Web.Users.Types
import Web.Users.Persistent.Definitions

import Control.Applicative ((<|>))
import Control.Monad
import Control.Monad.Trans.Maybe
import Control.Monad.Reader
#if MIN_VERSION_mtl(2,2,0)
import Control.Monad.Except
#else
import Control.Monad.Error
#endif
import Data.Typeable
import Data.Time.Clock
import Database.Persist
import Database.Persist.Sql
import qualified Database.Esqueleto as E
import qualified Data.Text as T
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID


#if MIN_VERSION_base(4,7,0)
deriving instance Typeable Key
#else
deriving instance Typeable1 Key
#endif

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

packLogin :: Monad m => User -> m (UTCTime -> Login)
packLogin usr =
    do p <-
           case u_password usr of
             PasswordHash p -> return p
             _ -> fail "Invalid password! Not hashed!"
       return $ \t ->
           Login
           { loginUsername = u_name usr
           , loginEmail = u_email usr
           , loginPassword = p
           , loginActive = u_active usr
           , loginCreatedAt = t
           }

unpackLogin :: Login -> User
unpackLogin l =
    (unpackLogin' l) { u_password = PasswordHidden }

unpackLogin' :: Login -> User
unpackLogin' l =
    User
    { u_name = loginUsername l
    , u_email = loginEmail l
    , u_password = PasswordHash (loginPassword l)
    , u_active = loginActive l
    }

mkTuple :: Entity Login -> (LoginId, User)
mkTuple entity =
    let user = unpackLogin (entityVal entity)
    in (entityKey entity, user)

compileField :: UserField -> (forall t. EntityField Login t -> a) -> a
compileField fld f =
    case fld of
      UserFieldId -> f LoginId
      UserFieldActive -> f LoginActive
      UserFieldEmail -> f LoginEmail
      UserFieldName -> f LoginUsername
      UserFieldPassword -> f LoginPassword

newtype Persistent = Persistent { runPersistent :: forall a. SqlPersistT IO a -> IO a }

instance UserStorageBackend Persistent where
    type UserId Persistent = LoginId
    initUserBackend conn =
        runPersistent conn $ runMigration migrateAll
    destroyUserBackend conn =
        runPersistent conn $
        do _ <- rawExecute "DROP TABLE IF EXISTS \"login\";" []
           _ <- rawExecute "DROP TABLE IF EXISTS \"login_token\";" []
           return ()
    housekeepBackend conn =
        do now <- getCurrentTime
           runPersistent conn $ deleteWhere [LoginTokenValidUntil <=. now]
    getUserIdByName conn userOrEmail =
        runPersistent conn $
        do mUserA <- getBy (UniqueUsername userOrEmail)
           mUserB <- getBy (UniqueEmail userOrEmail)
           return $ fmap entityKey (mUserA <|> mUserB)
    getUserById conn loginId =
        runPersistent conn $
        do mUser <- get loginId
           return $ fmap unpackLogin mUser
    listUsers conn mLimit sorter =
        runPersistent conn $
        do let orderOpts =
                 case sorter of
                   SortAsc t -> compileField t Asc
                   SortDesc t -> compileField t Desc
           xs <-
               case mLimit of
                 Nothing -> selectList [] [orderOpts]
                 Just (start, lim) ->
                   selectList []
                   [ orderOpts
                   , OffsetBy (fromIntegral start)
                   , LimitTo (fromIntegral lim)
                   ]
           return $ map mkTuple xs
    countUsers conn =
        liftM fromIntegral $
        runPersistent conn $ count ([] :: [Filter Login])
    createUser conn l =
        case packLogin l of
          Nothing -> return $ Left InvalidPassword
          Just mkUser ->
              do now <- getCurrentTime
                 let usr = mkUser now
                 runPersistent conn $
                   do mUsername <- selectFirst [LoginUsername ==. loginUsername usr] []
                      email <- emailInUse (loginEmail usr)
                      case (mUsername, email) of
                        (Just _, True) -> return $ Left UsernameAndEmailAlreadyTaken
                        (Just _, _) -> return $ Left UsernameAlreadyTaken
                        (Nothing, True)  -> return $ Left EmailAlreadyTaken
                        (Nothing, False) -> Right <$> insert usr
    updateUser conn userId updateFun =
        do mUser <- getUserById conn userId
           case mUser of
             Nothing ->
                 return $ Left UserDoesntExist
             Just origUser ->
                 runErrorT $
                 do let newUser = updateFun origUser
                    when (u_name newUser /= u_name origUser) $
                         do counter <- liftIO $ runPersistent conn $ count [LoginUsername ==. u_name newUser]
                            when (counter /= 0) $ throwError UsernameAlreadyExists
                    when (u_email newUser /= u_email origUser) $
                         do emailUsed <- liftIO $ runPersistent conn $ emailInUse (u_email newUser)
                            when emailUsed $ throwError EmailAlreadyExists
                    liftIO $ runPersistent conn $
                       do update userId [ LoginUsername =. u_name newUser
                                        , LoginEmail =. u_email newUser
                                        , LoginActive =. u_active newUser
                                        ]
                          case u_password newUser of
                            PasswordHash p -> update userId [ LoginPassword =. p ]
                            _ -> return ()
    deleteUser conn userId =
        runPersistent conn $ delete userId
    withAuthUser conn userOrEmail authFn action =
      runMaybeT $
      do login <- MaybeT . liftIO . runPersistent conn
                $ selectFirst ([LoginUsername ==. userOrEmail] ||. [LoginEmail ==. userOrEmail]) []
         let user = unpackLogin' $ entityVal login
         guard $ authFn user
         liftIO . action . entityKey $ login
    authUser conn userOrEmail pwd sessionTtl =
        withAuthUser conn userOrEmail (\user -> verifyPassword pwd $ u_password user) $ \userId ->
            SessionId <$> createToken conn "session" userId sessionTtl
    verifySession conn (SessionId sessionId) extendTime =
        do mUser <- getTokenOwner conn "session" sessionId
           case mUser of
             Nothing -> return Nothing
             Just userId ->
                 do extendToken conn "session" sessionId extendTime
                    return (Just userId)
    createSession conn userId sessionTtl =
        do mUser <- getUserById conn userId
           case (mUser :: Maybe User) of
             Nothing -> return Nothing
             Just _ -> Just . SessionId <$> createToken conn "session" userId sessionTtl
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

emailInUse :: MonadIO m => T.Text -> ReaderT SqlBackend m Bool
emailInUse email =
    do emailMatches <-
           E.select $
           E.from $ \login ->
           do E.where_ $ E.lower_ (login E.^. LoginEmail)
                            E.==. E.lower_ (E.val email)
              E.limit 1
              return login
       return (not $ null emailMatches)

createToken :: Persistent -> String -> LoginId -> NominalDiffTime -> IO T.Text
createToken conn tokenType userId timeToLive =
    runPersistent conn $
    do tok <- liftM (T.pack . UUID.toString) $ liftIO $ UUID.nextRandom
       now <- liftIO getCurrentTime
       _ <- insert $ LoginToken tok (T.pack tokenType) now (timeToLive `addUTCTime` now) userId
       return tok

deleteToken :: Persistent -> String -> T.Text -> IO ()
deleteToken conn tokenType token =
    runPersistent conn $
    case UUID.fromString (T.unpack token) of
      Nothing -> return ()
      Just _ ->
          do deleteBy (UniqueTypedToken token (T.pack tokenType))
             return ()

extendToken :: Persistent -> String -> T.Text -> NominalDiffTime -> IO ()
extendToken conn tokenType token timeToLive =
    runPersistent conn $
    case UUID.fromString (T.unpack token) of
      Nothing -> return ()
      Just _ ->
        do let selC = [LoginTokenTokenType ==. T.pack tokenType, LoginTokenToken ==. token]
           m <-
             selectFirst selC [Desc LoginTokenValidUntil]
           case m of
             Nothing -> return ()
             Just t ->
               do let validUntil =
                        loginTokenValidUntil (entityVal t)
                  now <- liftIO getCurrentTime
                  let extendedValid = timeToLive `addUTCTime` now
                  when (extendedValid > validUntil) $
                      updateWhere selC [LoginTokenValidUntil =. extendedValid]
                  return ()

getTokenOwner :: Persistent -> String -> T.Text -> IO (Maybe LoginId)
getTokenOwner conn tokenType token =
    runPersistent conn $
    case UUID.fromString (T.unpack token) of
      Nothing -> return Nothing
      Just _ ->
          do now <- liftIO $ getCurrentTime
             m <- selectFirst [LoginTokenTokenType ==. T.pack tokenType, LoginTokenToken ==. token, LoginTokenValidUntil >. now] []
             return $ fmap (loginTokenOwner . entityVal) m
