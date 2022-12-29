{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Data.Word              (Word64)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as B
import qualified Data.ByteString.Lazy   as BL
import qualified Data.ByteString.Base16 as B16

-- reference implementation
import qualified Data.Digest.Pure.SHA   as REF

-- implementation under test
import qualified Crypto.Hash.SHA384     as IUT

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck  as QC

vectors :: [ByteString]
vectors =
    [ ""
    , "The quick brown fox jumps over the lazy dog"
    , "The quick brown fox jumps over the lazy cog"
    , "abc"
    , "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    , "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    , B.replicate 1000000 0x61
    ]

answers :: [ByteString]
answers = map (B.filter (/= 0x20))
    [ "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    , "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
    , "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b"
    , "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    , "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
    , "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
    , "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
    ]

ansXLTest :: ByteString
ansXLTest = B.filter (/= 0x20)
    "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"

katTests :: [TestTree]
katTests
  | length vectors == length answers = map makeTest (zip3 [1::Int ..] vectors answers) ++ [xltest,xltest']
  | otherwise = error "vectors/answers length mismatch"
  where
    makeTest (i, v, r) = testGroup ("vec"++show i) $
        [ testCase "one-pass" (r @=? runTest v)
        , testCase "one-pass'" (r @=? runTest' v)
        , testCase "inc-1"    (r @=? runTestInc 1 v)
        , testCase "inc-2"    (r @=? runTestInc 2 v)
        , testCase "inc-3"    (r @=? runTestInc 3 v)
        , testCase "inc-4"    (r @=? runTestInc 4 v)
        , testCase "inc-5"    (r @=? runTestInc 5 v)
        , testCase "inc-7"    (r @=? runTestInc 7 v)
        , testCase "inc-8"    (r @=? runTestInc 8 v)
        , testCase "inc-9"    (r @=? runTestInc 9 v)
        , testCase "inc-16"   (r @=? runTestInc 16 v)
        , testCase "lazy-1"   (r @=? runTestLazy 1 v)
        , testCase "lazy-2"   (r @=? runTestLazy 2 v)
        , testCase "lazy-7"   (r @=? runTestLazy 7 v)
        , testCase "lazy-8"   (r @=? runTestLazy 8 v)
        , testCase "lazy-16"  (r @=? runTestLazy 16 v)
        , testCase "lazy-1'"   (r @=? runTestLazy' 1 v)
        , testCase "lazy-2'"   (r @=? runTestLazy' 2 v)
        , testCase "lazy-7'"   (r @=? runTestLazy' 7 v)
        , testCase "lazy-8'"   (r @=? runTestLazy' 8 v)
        , testCase "lazy-16'"  (r @=? runTestLazy' 16 v)
        ] ++
        [ testCase "lazy-63u"  (r @=? runTestLazyU 63 v) | B.length v > 63 ] ++
        [ testCase "lazy-65u"  (r @=? runTestLazyU 65 v) | B.length v > 65 ] ++
        [ testCase "lazy-97u"  (r @=? runTestLazyU 97 v) | B.length v > 97 ] ++
        [ testCase "lazy-131u" (r @=? runTestLazyU 131 v) | B.length v > 131 ] ++
        [ testCase "lazy-63u'"  (r @=? runTestLazyU' 63 v) | B.length v > 63 ] ++
        [ testCase "lazy-65u'"  (r @=? runTestLazyU' 65 v) | B.length v > 65 ] ++
        [ testCase "lazy-97u'"  (r @=? runTestLazyU' 97 v) | B.length v > 97 ] ++
        [ testCase "lazy-131u'" (r @=? runTestLazyU' 131 v) | B.length v > 131 ]

    runTest :: ByteString -> ByteString
    runTest = B16.encode . IUT.hash

    runTest' :: ByteString -> ByteString
    runTest' = B16.encode . IUT.finalize . IUT.start

    runTestInc :: Int -> ByteString -> ByteString
    runTestInc i = B16.encode . IUT.finalize . myfoldl' IUT.update IUT.init . splitB i

    runTestLazy :: Int -> ByteString -> ByteString
    runTestLazy i = B16.encode . IUT.hashlazy . BL.fromChunks . splitB i

    runTestLazy' :: Int -> ByteString -> ByteString
    runTestLazy' i = B16.encode . IUT.finalize . IUT.startlazy . BL.fromChunks . splitB i

    -- force unaligned md5-blocks
    runTestLazyU :: Int -> ByteString -> ByteString
    runTestLazyU i = B16.encode . IUT.hashlazy . BL.fromChunks . map B.copy . splitB i

    runTestLazyU' :: Int -> ByteString -> ByteString
    runTestLazyU' i = B16.encode . IUT.finalize . IUT.startlazy . BL.fromChunks . map B.copy . splitB i


    ----

    xltest = testGroup "XL-vec"
        [ testCase "inc" (ansXLTest @=? (B16.encode . IUT.hashlazy) vecXL) ]
      where
        vecXL = BL.fromChunks (replicate 16777216 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")

    xltest' = testGroup "XL-vec'"
        [ testCase "inc" (ansXLTest @=? (B16.encode . IUT.finalize . IUT.startlazy) vecXL) ]
      where
        vecXL = BL.fromChunks (replicate 16777216 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")


splitB :: Int -> ByteString -> [ByteString]
splitB l b
  | B.length b > l = b1 : splitB l b2
  | otherwise = [b]
  where
    (b1, b2) = B.splitAt l b


rfc4231Vectors :: [(ByteString,ByteString,ByteString)]
rfc4231Vectors = -- (secrect,msg,mac)
    [ (rep 20 0x0b, "Hi There", x"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
    , ("Jefe", "what do ya want for nothing?", x"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
    , (rep 20 0xaa, rep 50 0xdd, x"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27")
    , (B.pack [1..25], rep 50 0xcd, x"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb")
    , (rep 20 0x0c, "Test With Truncation", x"3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea")
    , (rep 131 0xaa, "Test Using Larger Than Block-Size Key - Hash Key First", x"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952")
    , (rep 131 0xaa, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", x"6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e")
    ]
  where
    x = B16.decodeLenient
    rep n c = B.replicate n c

rfc4231Tests :: [TestTree]
rfc4231Tests = zipWith makeTest [1::Int ..] rfc4231Vectors
  where
    makeTest i (key, msg, mac) = testGroup ("vec"++show i) $
        [ testCase "hmac" (hex mac  @=? hex (IUT.hmac key msg))
        , testCase "hmaclazy" (hex mac  @=? hex (IUT.hmaclazy key lazymsg))
        ]
      where
        lazymsg = BL.fromChunks . splitB 1 $ msg

    hex = B16.encode

-- define own 'foldl' here to avoid RULE rewriting to 'hashlazy'
myfoldl' :: (b -> a -> b) -> b -> [a] -> b
myfoldl' f z0 xs0 = lgo z0 xs0
  where
    lgo z []     = z
    lgo z (x:xs) = let z' = f z x
                   in z' `seq` lgo z' xs

newtype RandBS = RandBS { unRandBS :: ByteString }
newtype RandLBS = RandLBS BL.ByteString

instance Arbitrary RandBS where
    arbitrary = fmap (RandBS . B.pack) arbitrary
    shrink (RandBS x) = fmap RandBS (go x)
      where
        go bs = zipWith B.append (B.inits bs) (tail $ B.tails bs)

instance Show RandBS where
    show (RandBS x) = "RandBS {len=" ++ show (B.length x)++"}"

instance Arbitrary RandLBS where
    arbitrary = fmap (RandLBS . BL.fromChunks . map unRandBS) arbitrary

instance Show RandLBS where
    show (RandLBS x) = "RandLBS {len=" ++ show (BL.length x) ++ ", chunks=" ++ show (length $ BL.toChunks x)++"}"


refImplTests :: [TestTree]
refImplTests =
    [ testProperty "hash" prop_hash
    , testProperty "start" prop_start
    , testProperty "hashlazy" prop_hashlazy
    , testProperty "startlazy" prop_startlazy
    , testProperty "hashlazyAndLength" prop_hashlazyAndLength
    , testProperty "hmac" prop_hmac
    , testProperty "hmaclazy" prop_hmaclazy
    , testProperty "hmaclazyAndLength" prop_hmaclazyAndLength
    ]
  where
    prop_hash (RandBS bs)
        = ref_hash bs == IUT.hash bs

    prop_start (RandBS bs)
        = ref_hash bs == (IUT.finalize $ IUT.start bs)

    prop_hashlazy (RandLBS bs)
        = ref_hashlazy bs == IUT.hashlazy bs

    prop_hashlazyAndLength (RandLBS bs)
        = ref_hashlazyAndLength bs == IUT.hashlazyAndLength bs

    prop_startlazy (RandLBS bs)
        = ref_hashlazy bs == (IUT.finalize $ IUT.startlazy bs)

    prop_hmac (RandBS k) (RandBS bs)
        = ref_hmac k bs == IUT.hmac k bs

    prop_hmaclazy (RandBS k) (RandLBS bs)
        = ref_hmaclazy k bs == IUT.hmaclazy k bs

    prop_hmaclazyAndLength (RandBS k) (RandLBS bs)
        = ref_hmaclazyAndLength k bs == IUT.hmaclazyAndLength k bs

    ref_hash :: ByteString -> ByteString
    ref_hash = ref_hashlazy . fromStrict

    ref_hashlazy :: BL.ByteString -> ByteString
    ref_hashlazy = toStrict . REF.bytestringDigest . REF.sha384

    ref_hashlazyAndLength :: BL.ByteString -> (ByteString,Word64)
    ref_hashlazyAndLength x = (ref_hashlazy x, fromIntegral (BL.length x))

    ref_hmac :: ByteString -> ByteString -> ByteString
    ref_hmac secret = ref_hmaclazy secret . fromStrict

    ref_hmaclazy :: ByteString -> BL.ByteString -> ByteString
    ref_hmaclazy secret = toStrict . REF.bytestringDigest . REF.hmacSha384 (fromStrict secret)

    ref_hmaclazyAndLength :: ByteString -> BL.ByteString -> (ByteString,Word64)
    ref_hmaclazyAndLength secret msg = (ref_hmaclazy secret msg, fromIntegral (BL.length msg))

    -- toStrict/fromStrict only available with bytestring-0.10 and later
    toStrict = B.concat . BL.toChunks
    fromStrict = BL.fromChunks . (:[])

main :: IO ()
main = defaultMain $ testGroup "cryptohash-sha384"
    [ testGroup "KATs" katTests
    , testGroup "RFC4231" rfc4231Tests
    , testGroup "REF" refImplTests
    ]
