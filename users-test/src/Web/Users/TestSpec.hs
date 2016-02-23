{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}
module Web.Users.TestSpec
    ( makeUsersSpec )
where

import Web.Users.Types

import Control.Concurrent (threadDelay)
import Control.Monad
import Data.Aeson
import GHC.Generics
import Test.Hspec
import qualified Data.Text as T

type DummyUser = User DummyDetails

data DummyDetails
   = DummyDetails
   { dd_foo :: Bool
   , _dd_bar :: Int
   } deriving (Show, Eq, Generic)

instance FromJSON DummyDetails
instance ToJSON DummyDetails

mkUser :: T.Text -> T.Text -> DummyUser
mkUser name email =
    User
    { u_name = name
    , u_email = email
    , u_password = makePassword "1234"
    , u_active = False
    , u_more = DummyDetails True 21
    }

assertRight :: Show a => IO (Either a b) -> (b -> IO ()) -> IO ()
assertRight val action =
    do r <- val
       case r of
         Right v -> action v
         Left err -> expectationFailure (show err)

assertLeft :: IO (Either a b) -> String -> (a -> IO ()) -> IO ()
assertLeft val msg action =
    do r <- val
       case r of
         Right _ -> expectationFailure msg
         Left v -> action v

assertJust :: IO (Maybe a) -> String -> (a -> IO ()) -> IO ()
assertJust val msg action =
    do r <- val
       case r of
         Nothing -> expectationFailure msg
         Just v -> action v

makeUsersSpec :: forall b. UserStorageBackend b => b -> Spec
makeUsersSpec backend =
    before_ (initUserBackend backend) $
    after_ (destroyUserBackend backend) $
    do describe "core user management" $
           do it "should create valid users" $
                 assertRight (createUser backend userA) $ const (return ())
              it "should not allow duplicates" $
                 assertRight (createUser backend userB) $ \_ ->
                     do assertLeft (createUser backend (mkUser "foo2" "bar2@baz.com"))
                                       "succeeded to create foo2 bar2 again" $ \err ->
                            err `shouldBe` UsernameAndEmailAlreadyTaken
                        assertLeft (createUser backend (mkUser "foo2" "asdas@baz.com"))
                                       "succeeded to create foo2 with different email again" $ \err ->
                            err `shouldBe` UsernameAlreadyTaken
                        assertLeft (createUser backend (mkUser "asdas" "bar2@baz.com"))
                                       "succeeded to create different user with same email" $ \err ->
                            err `shouldBe` EmailAlreadyTaken
              it "list and count should be correct" $
                 assertRight (createUser backend userA) $ \userId1 ->
                 assertRight (createUser backend userB) $ \userId2 ->
                 do allUsers <- listUsers backend Nothing (SortAsc UserFieldId)
                    unless ((userId1, hidePassword userA) `elem` allUsers && (userId2, hidePassword userB) `elem` allUsers)
                           (expectationFailure $ "create users not in user list:" ++ show allUsers)
                    countUsers backend `shouldReturn` 2
              it "sorting should work" $
                 assertRight (createUser backend userA) $ \_ ->
                 assertRight (createUser backend userB) $ \_ ->
                 assertRight (createUser backend userC) $ \userId3 ->
                 do allUsers <- listUsers backend Nothing (SortAsc UserFieldName)
                    head allUsers `shouldBe` (userId3, hidePassword userC)
              it "updating and loading users should work" $
                 assertRight (createUser backend userA) $ \userIdA ->
                 assertRight (createUser backend userB) $ \_ ->
                     do assertRight (updateUser backend userIdA (\(user :: DummyUser) -> user { u_name = "changed" })) $ const (return ())
                        assertLeft (updateUser backend userIdA (\(user :: DummyUser) -> user { u_name = "foo2" }))
                                       "succeeded to set username to already used username" $ \err ->
                            err `shouldBe` UsernameAlreadyExists
                        assertLeft (updateUser backend userIdA (\(user :: DummyUser) -> user { u_email = "bar2@baz.com" }))
                                       "succeeded to set email to already used email" $ \err ->
                            err `shouldBe` EmailAlreadyExists
                        updateUserDetails backend userIdA (\d -> d { dd_foo = False })
                        userA' <- getUserById backend userIdA
                        userA' `shouldBe`
                               (Just $ (hidePassword userA)
                                { u_name = "changed"
                                , u_more =
                                    (u_more userA)
                                    { dd_foo = False
                                    }
                                })
                        userIdA' <- getUserIdByName backend "changed"
                        userIdA' `shouldBe` Just userIdA
              it "deleting users should work" $
                 assertRight (createUser backend userA) $ \userIdA ->
                 assertRight (createUser backend userB) $ \userIdB ->
                     do deleteUser backend userIdA
                        (allUsers :: [(UserId b, DummyUser)]) <-
                          listUsers backend Nothing (SortAsc UserFieldId)
                        map fst allUsers `shouldBe` [userIdB]
                        getUserById backend userIdA `shouldReturn` (Nothing :: Maybe DummyUser)
              it "reusing a deleted users name should work" $
                 assertRight (createUser backend userA) $ \userIdA ->
                     do deleteUser backend userIdA
                        assertRight (createUser backend userA) $ const (return ())
       describe "initialisation" $
           it "calling initUserBackend multiple times should not result in errors" $
              assertRight (createUser backend userA) $ \userIdA ->
              do initUserBackend backend
                 userA' <- getUserById backend userIdA
                 userA' `shouldBe` (Just $ hidePassword userA)
       describe "authentification" $
           do it "auth as valid user with username should work" $
                 withAuthedUser $ const (return ())
              it "auth as valid user with email should work" $
                 withAuthedUser' "bar@baz.com" "1234" 500 0 $ const (return ())
              it "auth with invalid credentials should fail" $
                 assertRight (createUser backend userA) $ \_ ->
                 do authUser backend "foo" (PasswordPlain "aaaa") 500 `shouldReturn` Nothing
                    authUser backend "foo" (PasswordPlain "123") 500 `shouldReturn` Nothing
                    authUser backend "bar@baz.com" (PasswordPlain "123") 500 `shouldReturn` Nothing
                    authUser backend "bar@baz.com' OR 1 = 1 --" (PasswordPlain "123") 500 `shouldReturn` Nothing
                    authUser backend "bar@baz.com' OR 1 = 1; --" (PasswordPlain  "' OR 1 = 1; --") 500 `shouldReturn` Nothing
              it "sessionless auth with valid userdata should work" $
                 assertRight (createUser backend userA) $ \userIdA ->
                 do withAuthUser backend "bar@baz.com" ((== DummyDetails True 21) . u_more) (return . (== userIdA)) `shouldReturn` Just True
                    withAuthUser backend "bar@baz.com" ((== DummyDetails True 21) . u_more) (return . (/= userIdA)) `shouldReturn` Just False
              it "sessionless auth with invalid userdata should fail" $
                 assertRight (createUser backend userA) $ \userIdA ->
                    withAuthUser backend "bar@baz.com" ((/= DummyDetails True 21) . u_more) (return . (/= userIdA)) `shouldReturn` Nothing
              it "forcing a session works" $
                 assertRight (createUser backend userA) $ \userIdA ->
                 assertJust (createSession backend userIdA 500) "session id missing" $ \_ -> return ()
              it "destroy session should really remove the session" $
                 withAuthedUser $ \(sessionId, _) ->
                     do destroySession backend sessionId
                        verifySession backend sessionId 0 `shouldReturn` (Nothing :: Maybe (UserId b))
              it "sessions should time out 1" $
                 withAuthedUserT 1 0 $ \(sessionId, _) ->
                 do threadDelay (seconds 1)
                    housekeepBackend backend
                    verifySession backend sessionId 0 `shouldReturn` (Nothing :: Maybe (UserId b))
              it "sessions should time out 2" $
                 withAuthedUserT 1 1 $ \(sessionId, _) ->
                 do threadDelay (seconds 2)
                    verifySession backend sessionId 0 `shouldReturn` (Nothing :: Maybe (UserId b))
       describe "password reset" $
          do it "generates a valid token for a user" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do token <- requestPasswordReset backend userIdA 500
                       verifyPasswordResetToken backend token `shouldReturn` (Just (hidePassword userA) :: Maybe DummyUser)
             it "a valid token should reset the password" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do withAuthedUserNoCreate "foo" "1234" 500 0 userIdA $ const (return ()) -- old login
                       token <- requestPasswordReset backend userIdA 500
                       housekeepBackend backend
                       verifyPasswordResetToken backend token `shouldReturn` (Just (hidePassword userA) :: Maybe DummyUser)
                       assertRight (applyNewPassword backend token $ makePassword "foobar") $ const $ return ()
                       withAuthedUserNoCreate "foo" "foobar" 500 0 userIdA $ const (return ()) -- new login
             it "expired tokens should not do any harm" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do withAuthedUserNoCreate "foo" "1234" 500 0 userIdA $ const (return ()) -- old login
                       token <- requestPasswordReset backend userIdA 1
                       threadDelay (seconds 1)
                       verifyPasswordResetToken backend token `shouldReturn` (Nothing :: Maybe DummyUser)
                       assertLeft (applyNewPassword backend token $ makePassword "foobar")
                                      "Reset password with expired token" $ const $ return ()
                       withAuthedUserNoCreate "foo" "1234" 500 0 userIdA $ const (return ()) -- still old login
             it "invalid tokens should not do any harm" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do withAuthedUserNoCreate "foo" "1234" 500 0 userIdA $ const (return ()) -- old login
                       let token = PasswordResetToken "Foooooooo!!!!"
                       verifyPasswordResetToken backend token `shouldReturn` (Nothing :: Maybe DummyUser)
                       assertLeft (applyNewPassword backend token $ makePassword "foobar")
                                      "Reset password with random token" $ const $ return ()
                       withAuthedUserNoCreate "foo" "1234" 500 0 userIdA $ const (return ()) -- still old login
       describe "user activation" $
          do it "activates a user with a valid activation token" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do token <- requestActivationToken backend userIdA 500
                       housekeepBackend backend
                       assertRight (activateUser backend token) $ const $ return ()
                       userA' <- getUserById backend userIdA
                       userA' `shouldBe`
                                  (Just $ (hidePassword userA)
                                   { u_active = True
                                   })
             it "does not allow expired tokens to activate a user" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do token <- requestActivationToken backend userIdA 1
                       threadDelay (seconds 1)
                       assertLeft (activateUser backend token) "expired token activated user" $ const $ return ()
                       userA' <- getUserById backend userIdA
                       userA' `shouldBe`
                                  (Just $ (hidePassword userA)
                                   { u_active = False
                                   })
             it "does not allow invalid tokens to activate a user" $
                assertRight (createUser backend userA) $ \userIdA ->
                    do let token = ActivationToken "aaaasdlasdkaklasdlkasjdl"
                       assertLeft (activateUser backend token) "invalid token activated user" $ const $ return ()
                       userA' <- getUserById backend userIdA
                       userA' `shouldBe`
                                  (Just $ (hidePassword userA)
                                   { u_active = False
                                   })
    where
      seconds x = x * 1000000
      userA = mkUser "foo" "bar@baz.com"
      userB = mkUser "foo2" "bar2@baz.com"
      userC = mkUser "alex" "aaaa@bbbbbb.com"
      withAuthedUser = withAuthedUser' "foo" "1234" 500 0
      withAuthedUserT = withAuthedUser' "foo" "1234"
      withAuthedUser' username pass sTime extTime action =
          assertRight (createUser backend userA) $ \userIdA ->
          withAuthedUserNoCreate username pass sTime extTime userIdA action
      withAuthedUserNoCreate username pass sTime extTime userIdA action =
          do mAuthRes <- authUser backend username (PasswordPlain pass) sTime
             case mAuthRes of
               Nothing ->
                   expectationFailure $ "Can not authenticate as user " ++ show username
               Just sessionId ->
                   do verifySession backend sessionId extTime `shouldReturn` Just userIdA
                      action (sessionId, userIdA)
