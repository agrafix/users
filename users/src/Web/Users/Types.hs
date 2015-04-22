{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
module Web.Users.Types
    ( -- * The core type class
      UserStorageBackend (..)
      -- * User representation
    , User(..), Password(..), makePassword, hidePassword
    , PasswordPlain(..), verifyPassword
      -- * Token types
    , PasswordResetToken(..), ActivationToken(..), SessionId(..)
      -- * Error types
    , CreateUserError(..), UpdateUserError(..)
    , TokenError(..)
    )
where

import Control.Applicative
import Crypto.BCrypt
import Data.Aeson
import Data.Int
import Data.Maybe
import Data.String
import Data.Time.Clock
import Data.Typeable
import Web.PathPieces
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified System.IO.Unsafe as U

-- | Errors that happen on storage level during user creation
data CreateUserError
   = UsernameOrEmailAlreadyTaken
   | InvalidPassword
   deriving (Show, Eq)

-- | Errors that happen on storage level during user updating
data UpdateUserError
   = UsernameOrEmailAlreadyExists
   | UserDoesntExit
   deriving (Show, Eq)

-- | Errors that happen on storage level during token actions
data TokenError
   = TokenInvalid
   deriving (Show, Eq)

-- | An abstract backend for managing users. A backend library should implement the interface and
-- an end user should build applications on top of this interface.
class (Show (UserId b), Eq (UserId b), ToJSON (UserId b), FromJSON (UserId b), Typeable (UserId b), PathPiece (UserId b)) => UserStorageBackend b where
    -- | The storage backends userid
    type UserId b :: *
    -- | Initialise the backend. Call once on application launch to for example create missing database tables
    initUserBackend :: b -> IO ()
    -- | Destory the backend. WARNING: This is only for testing! It deletes all tables and data.
    destroyUserBackend :: b -> IO ()
    -- | This cleans up invalid sessions and other tokens. Call periodically as needed.
    housekeepBackend :: b -> IO ()
    -- | Retrieve a user id from the database
    getUserIdByName :: b -> T.Text -> IO (Maybe (UserId b))
    -- | Retrieve a user from the database
    getUserById :: (FromJSON a, ToJSON a) => b -> UserId b -> IO (Maybe (User a))
    -- | List all users (unlimited, or limited)
    listUsers :: (FromJSON a, ToJSON a) => b -> Maybe (Int64, Int64) -> IO [(UserId b, User a)]
    -- | Count all users
    countUsers :: b -> IO Int64
    -- | Create a user
    createUser :: (FromJSON a, ToJSON a) => b -> User a -> IO (Either CreateUserError (UserId b))
    -- | Modify a user
    updateUser :: (FromJSON a, ToJSON a) => b -> UserId b -> (User a -> User a) -> IO (Either UpdateUserError ())
    -- | Modify details of a user
    updateUserDetails :: (FromJSON a, ToJSON a) => b -> UserId b -> (a -> a) -> IO ()
    updateUserDetails backend userId f =
        do _ <-
               updateUser backend userId $
                              \user ->
                                  user
                                  { u_more = f (u_more user)
                                  }
           return ()
    -- | Delete a user
    deleteUser :: b -> UserId b -> IO ()
    -- | Authentificate a user using username/email and password. The 'NominalDiffTime' describes the session duration
    authUser :: b -> T.Text -> PasswordPlain -> NominalDiffTime -> IO (Maybe SessionId)
    -- | Authentificate a user using username/email and password and execute a single action.
    withAuthUser :: b -> T.Text -> PasswordPlain -> (UserId b -> IO r) -> IO (Maybe r)
    -- | Authentificate a user using the additional info stored in the user record. The 'NominalDiffTime' describes the session duration
    authUserByUserData :: FromJSON a => b -> T.Text -> (a -> Bool) -> NominalDiffTime -> IO (Maybe SessionId)
    -- | Authentificate a user using the additional info stored in the user record and execute a single action.
    withAuthUserByUserData :: FromJSON a => b -> T.Text -> (a -> Bool) -> (UserId b -> IO r) -> IO (Maybe r)
    -- | Verify a 'SessionId'. The session duration can be extended by 'NominalDiffTime'
    verifySession :: b -> SessionId -> NominalDiffTime -> IO (Maybe (UserId b))
    -- | Destroy a session
    destroySession :: b -> SessionId -> IO ()
    -- | Request a 'PasswordResetToken' for a given user, valid for 'NominalDiffTime'
    requestPasswordReset :: b -> UserId b -> NominalDiffTime -> IO PasswordResetToken
    -- | Check if a 'PasswordResetToken' is still valid and retrieve the owner of it
    verifyPasswordResetToken :: (FromJSON a, ToJSON a) => b -> PasswordResetToken -> IO (Maybe (User a))
    -- | Apply a new password to the owner of 'PasswordResetToken' iff the token is still valid
    applyNewPassword :: b -> PasswordResetToken -> Password -> IO (Either TokenError ())
    -- | Request an 'ActivationToken' for a given user, valid for 'NominalDiffTime'
    requestActivationToken :: b -> UserId b -> NominalDiffTime -> IO ActivationToken
    -- | Activate the owner of 'ActivationToken' iff the token is still valid
    activateUser :: b -> ActivationToken -> IO (Either TokenError ())

-- | A password reset token to send out to users via email or sms
newtype PasswordResetToken
    = PasswordResetToken { unPasswordResetToken :: T.Text }
    deriving (Show, Eq, ToJSON, FromJSON, Typeable, PathPiece)

-- | An activation token to send out to users via email or sms
newtype ActivationToken
    = ActivationToken { unActivationToken :: T.Text }
    deriving (Show, Eq, ToJSON, FromJSON, Typeable, PathPiece)

-- | A session id for identifying user sessions
newtype SessionId
    = SessionId { unSessionId :: T.Text }
    deriving (Show, Eq, ToJSON, FromJSON, Typeable, PathPiece)

-- | Construct a password from plaintext by hashing it
makePassword :: PasswordPlain -> Password
makePassword (PasswordPlain plainText) =
    let hash =
            T.decodeUtf8 $ fromJustPass $ U.unsafePerformIO $
            hashPasswordUsingPolicy policy (T.encodeUtf8 plainText)
    in PasswordHash hash
    where
      policy =
          HashingPolicy
          { preferredHashCost = 8
          , preferredHashAlgorithm = "$2b$"
          }
      fromJustPass =
          fromMaybe (error "makePassword failed. This is probably a bcrypt library error")

-- | Check a plaintext password against a password
verifyPassword :: PasswordPlain -> Password -> Bool
verifyPassword (PasswordPlain plainText) pwd =
    case pwd of
      PasswordHidden -> False
      PasswordHash hash ->
          validatePassword (T.encodeUtf8 hash) (T.encodeUtf8 plainText)

-- | Plaintext passsword. Used for authentification.
newtype PasswordPlain
    = PasswordPlain { unPasswordPlain :: T.Text }
      deriving (Show, Eq, Typeable, IsString)

-- | Password representation. When updating or creating a user, use 'makePassword' to create one.
-- The implementation details of this type are ONLY for use in backend implementations.
data Password
   = PasswordHash !T.Text
   | PasswordHidden
    deriving (Show, Eq, Typeable)

-- | Strip the password from the user type.
hidePassword :: User a -> User a
hidePassword user =
    user { u_password = PasswordHidden }

-- | Core user datatype. Store custom information in the 'u_more' field
data User a
   = User
   { u_name :: !T.Text
   , u_email :: !T.Text
   , u_password :: !Password
   , u_active :: !Bool
   , u_more :: !a
   } deriving (Show, Eq, Typeable)

instance ToJSON a => ToJSON (User a) where
    toJSON (User name email _ active more) =
        object
        [ "name" .= name
        , "email" .= email
        , "active" .= active
        , "more" .= more
        ]

instance FromJSON a => FromJSON (User a) where
    parseJSON =
        withObject "User" $ \obj ->
            User <$> obj .: "name"
                 <*> obj .: "email"
                 <*> (parsePassword <$> (obj .:? "password"))
                 <*> obj .: "active"
                 <*> obj .: "more"
        where
          parsePassword maybePass =
              case maybePass of
                Nothing -> PasswordHidden
                Just pwd -> makePassword (PasswordPlain pwd)
