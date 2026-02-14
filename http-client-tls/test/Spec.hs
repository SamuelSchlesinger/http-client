{-# LANGUAGE OverloadedStrings #-}
import Test.Hspec
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.HTTP.Types
import Control.Monad (join)
import Data.Default
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra.Cipher as TLS

main :: IO ()
main = hspec $ do
    let params = (TLS.defaultParamsClient "" "")
            { TLS.clientSupported = def
                { TLS.supportedCiphers = TLS.ciphersuite_default
                , TLS.supportedVersions = [TLS.TLS13, TLS.TLS12]
                , TLS.supportedExtendedMainSecret = TLS.AllowEMS
                }
            }
        settings = mkManagerSettings params

    it "make a TLS connection" $ do
        manager <- newManager settings
        withResponse "https://httpbin.org/status/418" manager $ \res ->
            responseStatus res `shouldBe` status418

    it "digest authentication" $ do
        man <- newManager defaultManagerSettings
        req <- join $ applyDigestAuth
            "user"
            "passwd"
            "http://httpbin.org/digest-auth/qop/user/passwd"
            man
        response <- httpNoBody req man
        responseStatus response `shouldBe` status200

    it "incorrect digest authentication" $ do
        man <- newManager defaultManagerSettings
        join (applyDigestAuth "user" "passwd" "http://httpbin.org/" man)
            `shouldThrow` \(DigestAuthException _ _ det) ->
                det == UnexpectedStatusCode

    it "BadSSL: expired" $ do
        manager <- newManager settings
        let action = withResponse "https://expired.badssl.com/" manager (const (return ()))
        action `shouldThrow` anyException

    it "BadSSL: self-signed" $ do
        manager <- newManager settings
        let action = withResponse "https://self-signed.badssl.com/" manager (const (return ()))
        action `shouldThrow` anyException

    it "BadSSL: wrong.host" $ do
        manager <- newManager settings
        let action = withResponse "https://wrong.host.badssl.com/" manager (const (return ()))
        action `shouldThrow` anyException

    it "BadSSL: we do have case-insensitivity though" $ do
        manager <- newManager settings
        withResponse "https://BADSSL.COM" manager $ \res ->
            responseStatus res `shouldBe` status200

    it "accepts custom TLS settings (no cert validation)" $ do
        let noValidateParams = (TLS.defaultParamsClient "" "")
                { TLS.clientSupported = def
                    { TLS.supportedCiphers = TLS.ciphersuite_default
                    , TLS.supportedVersions = [TLS.TLS13, TLS.TLS12]
                    }
                , TLS.clientHooks = def
                    { TLS.onServerCertificate = \_ _ _ _ -> return []
                    }
                }
            noValidateSettings = mkManagerSettings noValidateParams
        manager <- newTlsManagerWith noValidateSettings
        let url = "https://wrong.host.badssl.com"
        request <- parseRequest url
        response <- httpNoBody request manager
        responseStatus response `shouldBe` status200

    it "global supports TLS" $ do
        manager <- getGlobalManager
        request <- parseRequest "https://httpbin.org"
        response <- httpNoBody request manager
        responseStatus response `shouldBe` status200
