{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
-- | Support for making connections via the boring-tls library.
--
-- Recommended reading: <https://haskell-lang.org/library/http-client>
module Network.HTTP.Client.TLS
    ( -- * Settings
      tlsManagerSettings
    , mkManagerSettings
    , mkManagerSettingsContext
    , newTlsManager
    , newTlsManagerWith
      -- * Digest authentication
    , applyDigestAuth
    , DigestAuthException (..)
    , DigestAuthExceptionDetails (..)
    , displayDigestAuthException
      -- * Global manager
    , getGlobalManager
    , setGlobalManager
    ) where

import Control.Applicative ((<|>))
import Control.Arrow (first)
import System.Environment (getEnvironment)
import Network.HTTP.Client hiding (host, port)
import Network.HTTP.Client.Internal hiding (host, port)
import Control.Exception
import Network.Socket (HostAddress)
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra.Cipher as TLS
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as LBS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad (guard, unless)
import qualified Data.CaseInsensitive as CI
import Data.Maybe (fromMaybe, isJust)
import Data.Default (def)
import Network.HTTP.Types (status401)
import Crypto.BoringSSL.Digest (Algorithm(..), hash)
import Data.ByteArray.Encoding (convertToBase, Base (Base16))
import Data.Typeable (Typeable)
import Control.Monad.Catch (MonadThrow, throwM)
import qualified Data.Map as Map
import qualified Data.Text as T
import Data.Text.Read (decimal)
import Control.Arrow ((***))

-- | Create a TLS-enabled 'ManagerSettings' with the given 'TLS.ClientParams'.
mkManagerSettings :: TLS.ClientParams
                  -> ManagerSettings
mkManagerSettings = mkManagerSettingsContext Nothing

-- | Same as 'mkManagerSettings', but also takes an optional
-- 'TLS.CertificateStore' to use as the system CA store. If 'Nothing',
-- the system certificate store will be loaded automatically.
--
-- @since 0.3.2
mkManagerSettingsContext
    :: Maybe TLS.CertificateStore
    -> TLS.ClientParams
    -> ManagerSettings
mkManagerSettingsContext mstore params = mkManagerSettingsContext' defaultManagerSettings mstore params

-- | Internal, creates manager settings with TLS support.
mkManagerSettingsContext'
    :: ManagerSettings
    -> Maybe TLS.CertificateStore
    -> TLS.ClientParams
    -> ManagerSettings
mkManagerSettingsContext' set mstore params = set
    { managerTlsConnection = getTlsConnection mstore params
    , managerTlsProxyConnection = getTlsProxyConnection mstore params
    , managerRawConnection = managerRawConnection defaultManagerSettings
    , managerRetryableException = \e ->
        case () of
            ()
                | ((fromException e)::(Maybe TLS.TLSException))==Just (TLS.PostHandshake TLS.Error_EOF) -> True
                | otherwise -> managerRetryableException defaultManagerSettings e
    , managerWrapException = \req ->
        let wrapper se
              | Just (_ :: IOException)          <- fromException se = se'
              | Just (_ :: TLS.TLSException)     <- fromException se = se'
              | otherwise = se
              where
                se' = toException $ HttpExceptionRequest req $ InternalException se
         in handle $ throwIO . wrapper
    }

-- | Default TLS-enabled manager settings.
--
-- Uses the system certificate store for validation, default cipher suites,
-- and TLS 1.2/1.3.
tlsManagerSettings :: ManagerSettings
tlsManagerSettings = unsafePerformIO $ do
    store <- TLS.getSystemCertificateStore
    let params = (TLS.defaultParamsClient "" "")
            { TLS.clientSupported = def
                { TLS.supportedCiphers  = TLS.ciphersuite_default
                , TLS.supportedVersions = [TLS.TLS13, TLS.TLS12]
                }
            , TLS.clientShared = def
                { TLS.sharedCAStore = store
                }
            }
    return $ mkManagerSettings params
{-# NOINLINE tlsManagerSettings #-}

-- | Create a TLS connection to the given host and port.
getTlsConnection :: Maybe TLS.CertificateStore
                 -> TLS.ClientParams
                 -> IO (Maybe HostAddress -> String -> Int -> IO Connection)
getTlsConnection mstore baseParams = do
    systemStore <- case mstore of
        Just s  -> return s
        Nothing -> TLS.getSystemCertificateStore
    return $ \_ha host port -> do
        let params = baseParams
                { TLS.clientServerIdentification = (strippedHostName host, S8.pack (show port))
                , TLS.clientShared = (TLS.clientShared baseParams)
                    { TLS.sharedCAStore = systemStore
                    }
                }
        bracketOnError
            (openSocket host port)
            NS.close
            $ \sock -> do
                ctx <- TLS.contextNew sock params
                TLS.handshake ctx
                makeConnection
                    (TLS.recvData ctx)
                    (\bs -> TLS.sendData ctx (LBS.fromStrict bs))
                    (TLS.bye ctx `catch` (\(_ :: SomeException) -> return ()) >> TLS.contextClose ctx)

getTlsProxyConnection
    :: Maybe TLS.CertificateStore
    -> TLS.ClientParams
    -> IO (S.ByteString -> (Connection -> IO ()) -> String -> Maybe HostAddress -> String -> Int -> IO Connection)
getTlsProxyConnection mstore baseParams = do
    systemStore <- case mstore of
        Just s  -> return s
        Nothing -> TLS.getSystemCertificateStore
    return $ \connstr checkConn serverName _ha host port -> do
        bracketOnError
            (openSocket host port)
            NS.close
            $ \sock -> do
                -- First, establish a plain connection to the proxy
                conn <- makeConnection
                    (NSB.recv sock 32752)
                    (NSB.sendAll sock)
                    (return ()) -- Don't close the socket yet

                -- Send CONNECT to the proxy
                connectionWrite conn connstr

                -- Let the caller verify the proxy connection
                checkConn conn

                -- Now upgrade to TLS on the same socket
                let params = baseParams
                        { TLS.clientServerIdentification = (strippedHostName serverName, S8.pack (show port))
                        , TLS.clientShared = (TLS.clientShared baseParams)
                            { TLS.sharedCAStore = systemStore
                            }
                        }
                ctx <- TLS.contextNew sock params
                TLS.handshake ctx

                makeConnection
                    (TLS.recvData ctx)
                    (\bs -> TLS.sendData ctx (LBS.fromStrict bs))
                    (TLS.bye ctx `catch` (\(_ :: SomeException) -> return ()) >> TLS.contextClose ctx)

-- | Open a TCP socket to the given host and port.
openSocket :: String -> Int -> IO NS.Socket
openSocket host port = do
    let hints = NS.defaultHints { NS.addrSocketType = NS.Stream }
    addrs <- NS.getAddrInfo (Just hints) (Just $ strippedHostName host) (Just $ show port)
    case addrs of
        []     -> fail $ "No addresses for " ++ host ++ ":" ++ show port
        addr:_ -> do
            sock <- NS.openSocket addr
            NS.connect sock (NS.addrAddress addr)
            return sock

-- | Load up a new TLS manager with default settings, respecting proxy
-- environment variables.
--
-- @since 0.3.4
newTlsManager :: MonadIO m => m Manager
newTlsManager = liftIO $ newManager tlsManagerSettings

-- | Load up a new TLS manager based upon specified settings.
--
-- @since 0.3.5
newTlsManagerWith :: MonadIO m => ManagerSettings -> m Manager
newTlsManagerWith set = liftIO $ newManager set

-- | Evil global manager, to make life easier for the common use case
globalManager :: IORef Manager
globalManager = unsafePerformIO $ newTlsManager >>= newIORef
{-# NOINLINE globalManager #-}

-- | Get the current global 'Manager'
--
-- @since 0.2.4
getGlobalManager :: IO Manager
getGlobalManager = readIORef globalManager
{-# INLINE getGlobalManager #-}

-- | Set the current global 'Manager'
--
-- @since 0.2.4
setGlobalManager :: Manager -> IO ()
setGlobalManager = writeIORef globalManager

-- | Generated by 'applyDigestAuth' when it is unable to apply the
-- digest credentials to the request.
--
-- @since 0.3.3
data DigestAuthException
    = DigestAuthException Request (Response ()) DigestAuthExceptionDetails
    deriving (Show, Typeable)
instance Exception DigestAuthException where
    displayException = displayDigestAuthException

-- | User friendly display of a 'DigestAuthException'
--
-- @since 0.3.3
displayDigestAuthException :: DigestAuthException -> String
displayDigestAuthException (DigestAuthException req res det) = concat
    [ "Unable to submit digest credentials due to: "
    , details
    , ".\n\nRequest: "
    , show req
    , ".\n\nResponse: "
    , show res
    ]
  where
    details =
        case det of
            UnexpectedStatusCode -> "received unexpected status code"
            MissingWWWAuthenticateHeader ->
                "missing WWW-Authenticate response header"
            WWWAuthenticateIsNotDigest ->
                "WWW-Authenticate response header does not indicate Digest"
            MissingRealm ->
                "WWW-Authenticate response header does include realm"
            MissingNonce ->
                "WWW-Authenticate response header does include nonce"

-- | Detailed explanation for failure for 'DigestAuthException'
--
-- @since 0.3.3
data DigestAuthExceptionDetails
    = UnexpectedStatusCode
    | MissingWWWAuthenticateHeader
    | WWWAuthenticateIsNotDigest
    | MissingRealm
    | MissingNonce
    deriving (Show, Read, Typeable, Eq, Ord)

-- | Apply digest authentication to this request.
--
-- Note that this function will need to make an HTTP request to the
-- server in order to get the nonce, thus the need for a @Manager@ and
-- to live in @IO@. This also means that the request body will be sent
-- to the server. If the request body in the supplied @Request@ can
-- only be read once, you should replace it with a dummy value.
--
-- In the event of successfully generating a digest, this will return
-- a @Just@ value. If there is any problem with generating the digest,
-- it will return @Nothing@.
--
-- @since 0.3.1
applyDigestAuth :: (MonadIO m, MonadThrow n)
                => S.ByteString -- ^ username
                -> S.ByteString -- ^ password
                -> Request
                -> Manager
                -> m (n Request)
applyDigestAuth user pass req0 man = liftIO $ do
    res <- httpNoBody req man
    let throw' = throwM . DigestAuthException req res
    return $ do
        unless (responseStatus res == status401)
            $ throw' UnexpectedStatusCode
        h1 <- maybe (throw' MissingWWWAuthenticateHeader) return
            $ lookup "WWW-Authenticate" $ responseHeaders res
        h2 <- maybe (throw' WWWAuthenticateIsNotDigest) return
            $ stripCI "Digest " h1
        let pieces = map (strip *** strip) (toPairs h2)
        realm <- maybe (throw' MissingRealm) return
               $ lookup "realm" pieces
        nonce <- maybe (throw' MissingNonce) return
               $ lookup "nonce" pieces
        let qop = isJust $ lookup "qop" pieces
            digest
                | qop = md5 $ S.concat
                    [ ha1
                    , ":"
                    , nonce
                    , ":00000001:deadbeef:auth:"
                    , ha2
                    ]
                | otherwise = md5 $ S.concat [ha1, ":", nonce, ":", ha2]
              where
                ha1 = md5 $ S.concat [user, ":", realm, ":", pass]

                -- we always use no qop or qop=auth
                ha2 = md5 $ S.concat [method req, ":", path req]

                md5 bs = convertToBase Base16 (hash MD5 bs)
            key = "Authorization"
            val = S.concat
                [ "Digest username=\""
                , user
                , "\", realm=\""
                , realm
                , "\", nonce=\""
                , nonce
                , "\", uri=\""
                , path req
                , "\", response=\""
                , digest
                , "\""
                -- FIXME algorithm?
                , case lookup "opaque" pieces of
                    Nothing -> ""
                    Just o -> S.concat [", opaque=\"", o, "\""]
                , if qop
                    then ", qop=auth, nc=00000001, cnonce=\"deadbeef\""
                    else ""
                ]
        return req
            { requestHeaders = (key, val)
                             : filter
                                    (\(x, _) -> x /= key)
                                    (requestHeaders req)
            , cookieJar = Just $ responseCookieJar res
            }
  where
    -- Since we're expecting a non-200 response, ensure we do not
    -- throw exceptions for such responses.
    req = req0 { checkResponse = \_ _ -> return () }

    stripCI x y
        | CI.mk x == CI.mk (S.take len y) = Just $ S.drop len y
        | otherwise = Nothing
      where
        len = S.length x

    _comma = 44
    _equal = 61
    _dquot = 34
    _space = 32

    strip = fst . S.spanEnd (== _space) . S.dropWhile (== _space)

    toPairs bs0
        | S.null bs0 = []
        | otherwise =
            let bs1 = S.dropWhile (== _space) bs0
                (key, bs2) = S.break (\w -> w == _equal || w == _comma) bs1
             in case () of
                  ()
                    | S.null bs2 -> [(key, "")]
                    | S.head bs2 == _equal ->
                        let (val, rest) = parseVal $ S.tail bs2
                         in (key, val) : toPairs rest
                    | otherwise ->
                        assert (S.head bs2 == _comma) $
                        (key, "") : toPairs (S.tail bs2)

    parseVal bs0 = fromMaybe (parseUnquoted bs0) $ do
        guard $ not $ S.null bs0
        guard $ S.head bs0 == _dquot
        let (x, y) = S.break (== _dquot) $ S.tail bs0
        guard $ not $ S.null y
        Just (x, S.drop 1 $ S.dropWhile (/= _comma) y)

    parseUnquoted bs =
        let (x, y) = S.break (== _comma) bs
         in (x, S.drop 1 y)
