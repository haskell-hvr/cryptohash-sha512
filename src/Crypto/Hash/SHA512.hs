-- |
-- Module      : Crypto.Hash.SHA512
-- License     : BSD-style
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
-- Portability : unknown
--
-- A module containing <https://en.wikipedia.org/wiki/SHA-2 SHA-512> bindings
--
module Crypto.Hash.SHA512
    (

    -- * Incremental API
    --
    -- | This API is based on 4 different functions, similar to the
    -- lowlevel operations of a typical hash:
    --
    --  - 'init': create a new hash context
    --  - 'update': update non-destructively a new hash context with a strict bytestring
    --  - 'updates': same as update, except that it takes a list of strict bytestrings
    --  - 'finalize': finalize the context and returns a digest bytestring.
    --
    -- all those operations are completely pure, and instead of
    -- changing the context as usual in others language, it
    -- re-allocates a new context each time.
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA512 as SHA512
    -- >
    -- > main = print digest
    -- >   where
    -- >     digest = SHA512.finalize ctx
    -- >     ctx    = foldl SHA512.update ctx0 (map Data.ByteString.pack [ [1,2,3], [4,5,6] ])
    -- >     ctx0   = SHA512.init

      Ctx(..)
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString
    , start    -- :: ByteString -> Ct
    , startlazy -- :: L.ByteString -> Ctx


    -- * Single Pass API
    --
    -- | This API use the incremental API under the hood to provide
    -- the common all-in-one operations to create digests out of a
    -- 'ByteString' and lazy 'L.ByteString'.
    --
    --  - 'hash': create a digest ('init' + 'update' + 'finalize') from a strict 'ByteString'
    --  - 'hashlazy': create a digest ('init' + 'update' + 'finalize') from a lazy 'L.ByteString'
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA512 as SHA512
    -- >
    -- > main = print $ SHA512.hash (Data.ByteString.pack [0..255])
    --
    -- __NOTE__: The returned digest is a binary 'ByteString'. For
    -- converting to a base16/hex encoded digest the
    -- <https://hackage.haskell.org/package/base16-bytestring base16-bytestring>
    -- package is recommended.

    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: L.ByteString -> ByteString

    -- ** HMAC-SHA-512
    --
    -- | <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
    -- <https://en.wikipedia.org/wiki/HMAC HMAC>-SHA-512 digests

    , hmac     -- :: ByteString -> ByteString -> ByteString
    , hmaclazy -- :: ByteString -> L.ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Foreign.C.Types
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, toForeignPtr, memcpy)
import Data.Bits (xor)
import Data.Word
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | perform IO for hashes that do allocation and ffi.
-- unsafeDupablePerformIO is used when possible as the
-- computation is pure and the output is directly linked
-- to the input. we also do not modify anything after it has
-- been returned to the user.
unsafeDoIO :: IO a -> a
unsafeDoIO = unsafeDupablePerformIO

-- | SHA-512 Context
--
-- The context data is exactly 208 bytes long, however
-- the data in the context is stored in host-endianness.
--
-- The context data is made up of
--
--  * Two 'Word64's representing the number of bytes already feed to hash algorithm so far (lower word first),
--
--  * a 128-element 'Word8' buffer holding partial input-chunks, and finally
--
--  * a 8-element 'Word64' array holding the current work-in-progress digest-value.
--
-- Consequently, a SHA-512 digest as produced by 'hash', 'hashlazy', or 'finalize' is 64 bytes long.
newtype Ctx = Ctx ByteString
  deriving (Eq)

-- keep this synchronised with cbits/sha512.h
{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 64

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 208

{-# RULES "digestSize" B.length (finalize init) = digestSize #-}
{-# RULES "hash" forall b. finalize (update init b) = hash b #-}
{-# RULES "hash.list1" forall b. finalize (updates init [b]) = hash b #-}
{-# RULES "hashmany" forall b. finalize (foldl update init b) = hashlazy (L.fromChunks b) #-}
{-# RULES "hashlazy" forall b. finalize (foldl update init $ L.toChunks b) = hashlazy b #-}

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

copyCtx :: Ptr Ctx -> Ptr Ctx -> IO ()
copyCtx dst src = memcpy (castPtr dst) (castPtr src) (fromIntegral sizeCtx)

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx ctxB) f = Ctx `fmap` createCtx
  where
    createCtx = create sizeCtx $ \dstPtr ->
                withByteStringPtr ctxB $ \srcPtr -> do
                    copyCtx (castPtr dstPtr) (castPtr srcPtr)
                    f (castPtr dstPtr)

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx ctxB) f =
    allocaBytes sizeCtx $ \dstPtr ->
    withByteStringPtr ctxB $ \srcPtr -> do
        copyCtx (castPtr dstPtr) (castPtr srcPtr)
        f (castPtr dstPtr)

withCtxNew :: (Ptr Ctx -> IO ()) -> IO Ctx
withCtxNew f = Ctx `fmap` create sizeCtx (f . castPtr)

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = allocaBytes sizeCtx (f . castPtr)

foreign import ccall unsafe "sha512.h hs_cryptohash_sha512_init"
    c_sha512_init :: Ptr Ctx -> IO ()

foreign import ccall unsafe "sha512.h hs_cryptohash_sha512_update"
    c_sha512_update_unsafe :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()

foreign import ccall safe "sha512.h hs_cryptohash_sha512_update"
    c_sha512_update_safe :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()

-- 'safe' call overhead neglible for 4KiB and more
c_sha512_update :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()
c_sha512_update pctx pbuf sz
  | sz < 4096 = c_sha512_update_unsafe pctx pbuf sz
  | otherwise = c_sha512_update_safe   pctx pbuf sz

foreign import ccall unsafe "sha512.h hs_cryptohash_sha512_finalize"
    c_sha512_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_sha512_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr = create digestSize (c_sha512_finalize ptr)

{-# NOINLINE init #-}
-- | create a new hash context
init :: Ctx
init = unsafeDoIO $ withCtxNew $ c_sha512_init

validCtx :: Ctx -> Bool
validCtx (Ctx b) = B.length b == sizeCtx

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d
  | validCtx ctx = unsafeDoIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d
  | otherwise    = error "SHA512.update: invalid Ctx"

{-# NOINLINE updates #-}
-- | updates a context with multiple bytestrings
updates :: Ctx -> [ByteString] -> Ctx
updates ctx d
  | validCtx ctx = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (updateInternalIO ptr) d
  | otherwise    = error "SHA512.updates: invalid Ctx"

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring (64 bytes)
finalize :: Ctx -> ByteString
finalize ctx
  | validCtx ctx = unsafeDoIO $ withCtxThrow ctx finalizeInternalIO
  | otherwise    = error "SHA512.finalize: invalid Ctx"

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring (64 bytes)
hash :: ByteString -> ByteString
hash d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_sha512_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE start #-}
-- | hash a strict bytestring into a Ctx
start :: ByteString -> Ctx
start d = unsafeDoIO $ withCtxNew $ \ptr -> do
    c_sha512_init ptr >> updateInternalIO ptr d

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring (64 bytes)
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_sha512_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr

{-# NOINLINE startlazy #-}
-- | hash a lazy bytestring into a Ctx
startlazy :: L.ByteString -> Ctx
startlazy l = unsafeDoIO $ withCtxNew $ \ptr -> do
    c_sha512_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l)

{-# NOINLINE hmac #-}
-- | Compute 64-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-SHA-512 digest for a strict bytestring message
--
-- @since 0.11.100.0
hmac :: ByteString -- ^ secret
     -> ByteString -- ^ message
     -> ByteString
hmac secret msg = hash $ B.append opad (hash $ B.append ipad msg)
  where
    opad = B.map (xor 0x5c) k'
    ipad = B.map (xor 0x36) k'

    k'  = B.append kt pad
    kt  = if B.length secret > 128 then hash secret else secret
    pad = B.replicate (128 - B.length kt) 0


{-# NOINLINE hmaclazy #-}
-- | Compute 64-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-SHA-512 digest for a lazy bytestring message
--
-- @since 0.11.100.0
hmaclazy :: ByteString   -- ^ secret
         -> L.ByteString -- ^ message
         -> ByteString
hmaclazy secret msg = hash $ B.append opad (hashlazy $ L.append ipad msg)
  where
    opad = B.map (xor 0x5c) k'
    ipad = L.fromChunks [B.map (xor 0x36) k']

    k'  = B.append kt pad
    kt  = if B.length secret > 128 then hash secret else secret
    pad = B.replicate (128 - B.length kt) 0
