{-# LANGUAGE Trustworthy #-}
-- |
-- Module      : Crypto.Hash.SHA384
-- License     : BSD-style
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
-- Portability : unknown
--
-- A module containing <https://en.wikipedia.org/wiki/SHA-2 SHA-384> bindings
--
-- @since 0.11.102.0
module Crypto.Hash.SHA384
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
    -- > import qualified Crypto.Hash.SHA384 as SHA384
    -- >
    -- > main = print digest
    -- >   where
    -- >     digest = SHA384.finalize ctx
    -- >     ctx    = foldl SHA384.update ctx0 (map Data.ByteString.pack [ [1,2,3], [4,5,6] ])
    -- >     ctx0   = SHA384.init

      Ctx(..)
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString
    , finalizeAndLength -- :: Ctx -> (ByteString,Word64)
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
    -- > import qualified Crypto.Hash.SHA384 as SHA384
    -- >
    -- > main = print $ SHA384.hash (Data.ByteString.pack [0..255])
    --
    -- __NOTE__: The returned digest is a binary 'ByteString'. For
    -- converting to a base16/hex encoded digest the
    -- <https://hackage.haskell.org/package/base16-bytestring base16-bytestring>
    -- package is recommended.

    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: L.ByteString -> ByteString
    , hashlazyAndLength -- :: L.ByteString -> (ByteString,Word64)

    -- ** HMAC-SHA-384
    --
    -- | <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
    -- <https://en.wikipedia.org/wiki/HMAC HMAC>-SHA-384 digests

    , hmac     -- :: ByteString -> ByteString -> ByteString
    , hmaclazy -- :: ByteString -> L.ByteString -> ByteString
    , hmaclazyAndLength -- :: ByteString -> L.ByteString -> (ByteString,Word64)
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
import Data.ByteString.Internal (create, toForeignPtr, memcpy, mallocByteString)
import Data.Bits (xor)
import Data.Word
import System.IO.Unsafe (unsafeDupablePerformIO)

import Compat (constructBS)
import Crypto.Hash.SHA512.FFI

-- | perform IO for hashes that do allocation and ffi.
-- unsafeDupablePerformIO is used when possible as the
-- computation is pure and the output is directly linked
-- to the input. we also do not modify anything after it has
-- been returned to the user.
unsafeDoIO :: IO a -> a
unsafeDoIO = unsafeDupablePerformIO

-- keep this synchronised with cbits/sha512.h
{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 48

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 208

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

{-# INLINE create' #-}
-- | Variant of 'create' which allows to return an argument
create' :: Int -> (Ptr Word8 -> IO a) -> IO (ByteString,a)
create' l f = do
    fp <- mallocByteString l
    x <- withForeignPtr fp $ \p -> f p
    let bs = constructBS fp l
    return $! x `seq` bs `seq` (bs,x)

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

-- 'safe' call overhead neglible for 4KiB and more
c_sha512_update :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()
c_sha512_update pctx pbuf sz
  | sz < 4096 = c_sha512_update_unsafe pctx pbuf sz
  | otherwise = c_sha512_update_safe   pctx pbuf sz

-- 'safe' call overhead neglible for 4KiB and more
c_sha384_hash :: Ptr Word8 -> CSize -> Ptr Word8 -> IO ()
c_sha384_hash pbuf sz pout
  | sz < 4096 = c_sha384_hash_unsafe pbuf sz pout
  | otherwise = c_sha384_hash_safe   pbuf sz pout

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_sha512_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr = create digestSize (c_sha512t_finalize ptr 384)

finalizeInternalIO' :: Ptr Ctx -> IO (ByteString,Word64)
finalizeInternalIO' ptr = create' digestSize (c_sha512t_finalize_len ptr 384)

{-# NOINLINE init #-}
-- | create a new hash context
init :: Ctx
init = unsafeDoIO $ withCtxNew $ c_sha384_init

validCtx :: Ctx -> Bool
validCtx (Ctx b) = B.length b == sizeCtx

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d
  | validCtx ctx = unsafeDoIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d
  | otherwise    = error "SHA384.update: invalid Ctx"

{-# NOINLINE updates #-}
-- | updates a context with multiple bytestrings
updates :: Ctx -> [ByteString] -> Ctx
updates ctx d
  | validCtx ctx = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (updateInternalIO ptr) d
  | otherwise    = error "SHA384.updates: invalid Ctx"

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring (48 bytes)
finalize :: Ctx -> ByteString
finalize ctx
  | validCtx ctx = unsafeDoIO $ withCtxThrow ctx finalizeInternalIO
  | otherwise    = error "SHA384.finalize: invalid Ctx"

{-# NOINLINE finalizeAndLength #-}
-- | Variant of 'finalize' also returning length of hashed content
finalizeAndLength :: Ctx -> (ByteString,Word64)
finalizeAndLength ctx
  | validCtx ctx = unsafeDoIO $ withCtxThrow ctx finalizeInternalIO'
  | otherwise    = error "SHA384.finalize: invalid Ctx"

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring (48 bytes)
hash :: ByteString -> ByteString
-- hash d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do c_sha384_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr
hash d = unsafeDoIO $ unsafeUseAsCStringLen d $ \(cs, len) -> create digestSize (c_sha384_hash (castPtr cs) (fromIntegral len))

{-# NOINLINE start #-}
-- | hash a strict bytestring into a Ctx
start :: ByteString -> Ctx
start d = unsafeDoIO $ withCtxNew $ \ptr -> do
    c_sha384_init ptr >> updateInternalIO ptr d

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring (48 bytes)
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_sha384_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr

{-# NOINLINE hashlazyAndLength #-}
-- | Variant of 'hashlazy' which simultaneously computes the hash and length of a lazy bytestring.
hashlazyAndLength :: L.ByteString -> (ByteString,Word64)
hashlazyAndLength l = unsafeDoIO $ withCtxNewThrow $ \ptr ->
    c_sha384_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO' ptr

{-# NOINLINE startlazy #-}
-- | hash a lazy bytestring into a Ctx
startlazy :: L.ByteString -> Ctx
startlazy l = unsafeDoIO $ withCtxNew $ \ptr -> do
    c_sha384_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l)

{-# NOINLINE hmac #-}
-- | Compute 48-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-SHA-384 digest for a strict bytestring message
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
-- | Compute 48-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-SHA-384 digest for a lazy bytestring message
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

-- | Variant of 'hmaclazy' which also returns length of message
hmaclazyAndLength :: ByteString   -- ^ secret
                  -> L.ByteString -- ^ message
                  -> (ByteString,Word64) -- ^ digest (48 bytes) and length of message
hmaclazyAndLength secret msg =
    (hash (B.append opad htmp), sz' - fromIntegral ipadLen)
  where
    (htmp, sz') = hashlazyAndLength (L.append ipad msg)

    opad = B.map (xor 0x5c) k'
    ipad = L.fromChunks [B.map (xor 0x36) k']
    ipadLen = B.length k'

    k'  = B.append kt pad
    kt  = if B.length secret > 128 then hash secret else secret
    pad = B.replicate (128 - B.length kt) 0