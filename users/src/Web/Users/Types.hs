{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ConstraintKinds #-}
module Web.Users.Types
    ( -- * The core type class
      UserStorageBackend (..)
      -- * User representation
    , User(..), Password(..), makePassword, hidePassword
    , PasswordPlain(..), verifyPassword
    , UserField(..)
      -- * Token types
    , PasswordResetToken(..), ActivationToken(..), SessionId(..)
      -- * Error types
    , CreateUserError(..), UpdateUserError(..)
    , TokenError(..)
      -- * Helper typed
    , SortBy(..)
    )
where

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
   = InvalidPassword
   | UsernameAlreadyTaken
   | EmailAlreadyTaken
   | UsernameAndEmailAlreadyTaken
   deriving (Show, Eq)

-- | Errors that happen on storage level during user updating
data UpdateUserError
   = UsernameAlreadyExists
   | EmailAlreadyExists
   | UserDoesntExist
   deriving (Show, Eq)

-- | Errors that happen on storage level during token actions
data TokenError
   = TokenInvalid
   deriving (Show, Eq)

-- | Sorting direction
data SortBy t
   = SortAsc t
   | SortDesc t

-- | Backend constraints
type IsUserBackend b =
  ( Show (UserId b)
  , Eq (UserId b)
  , ToJSON (UserId b)
  , FromJSON (UserId b)
  , Typeable (UserId b)
  , PathPiece (UserId b)
  )

-- | An abstract backend for managing users. A backend library should implement the interface and
-- an end user should build applications on top of this interface.
class IsUserBackend b => UserStorageBackend b where
    -- | The storage backends userid
    type UserId b :: *
    -- | Initialise the backend. Call once on application launch to for
    -- example create missing database tables
    initUserBackend :: b -> IO ()
    -- | Destory the backend. WARNING: This is only for testing! It deletes all tables and data.
    destroyUserBackend :: b -> IO ()
    -- | This cleans up invalid sessions and other tokens. Call periodically as needed.
    housekeepBackend :: b -> IO ()
    -- | Retrieve a user id from the database by name or email
    getUserIdByName :: b -> T.Text -> IO (Maybe (UserId b))
    -- | Retrieve a user from the database
    getUserById :: b -> UserId b -> IO (Maybe User)
    -- | List all users unlimited, or limited, sorted by a 'UserField'
    listUsers :: b -> Maybe (Int64, Int64) -> SortBy UserField -> IO [(UserId b, User)]
    -- | Count all users
    countUsers :: b -> IO Int64
    -- | Create a user
    createUser :: b -> User -> IO (Either CreateUserError (UserId b))
    -- | Modify a user
    updateUser :: b -> UserId b -> (User -> User) -> IO (Either UpdateUserError ())
    -- | Delete a user
    deleteUser :: b -> UserId b -> IO ()
    -- | Authentificate a user using username/email and password. The 'NominalDiffTime' describes the session duration
    authUser :: b -> T.Text -> PasswordPlain -> NominalDiffTime -> IO (Maybe SessionId)
    -- | Authentificate a user and execute a single action.
    withAuthUser :: b -> T.Text -> (User -> Bool) -> (UserId b -> IO r) -> IO (Maybe r)
    -- | Verify a 'SessionId'. The session duration can be extended by 'NominalDiffTime'
    verifySession :: b -> SessionId -> NominalDiffTime -> IO (Maybe (UserId b))
    -- | Force create a session for a user. This is useful for support/admin login.
    -- If the user does not exist, this will fail.
    createSession :: b -> UserId b -> NominalDiffTime -> IO (Maybe SessionId)
    -- | Destroy a session
    destroySession :: b -> SessionId -> IO ()
    -- | Request a 'PasswordResetToken' for a given user, valid for 'NominalDiffTime'
    requestPasswordReset :: b -> UserId b -> NominalDiffTime -> IO PasswordResetToken
    -- | Check if a 'PasswordResetToken' is still valid and retrieve the owner of it
    verifyPasswordResetToken :: b -> PasswordResetToken -> IO (Maybe User)
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
hidePassword :: User -> User
hidePassword user =
    user { u_password = PasswordHidden }

-- | Fields of user datatype
data UserField
   = UserFieldId
   | UserFieldName
   | UserFieldEmail
   | UserFieldPassword
   | UserFieldActive
     deriving (Show, Eq)

-- | Core user datatype
data User
   = User
   { u_name :: !T.Text
   , u_email :: !T.Text
   , u_password :: !Password
   , u_active :: !Bool
   } deriving (Show, Eq, Typeable)

instance ToJSON User where
    toJSON (User name email _ active) =
        object
        [ "name" .= name
        , "email" .= email
        , "active" .= active
        ]

instance FromJSON User where
    parseJSON =
        withObject "User" $ \obj ->
            User <$> obj .: "name"
                 <*> obj .: "email"
                 <*> (parsePassword <$> (obj .:? "password"))
                 <*> obj .: "active"
        where
          parsePassword maybePass =
              case maybePass of
                Nothing -> PasswordHidden
                Just pwd -> makePassword (PasswordPlain pwd)
