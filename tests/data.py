from ain.types import ECIESEncrypted, SetOperation, TransactionBody
from ain.utils import V3Keystore

"""
The data in this file is for running test ONLY. Do NOT use it for production.
"""
address = "0xCAcD898dBaEdBD9037aCd25b82417587E972838d"
pk = bytes.fromhex("cf0ba8241cd1452c282c4dfa33d48e43ca34e60f5da9a2422293aa34ac14b018991d0cbc42089e4dcf3b3cc2907d51f06baed00cad7f855182572c77cbfad2b3")
sk = bytes.fromhex("cef602325bc0882591e5768e94cd94a326947e8ee5d3b02fb29d1b89a9334d99")
mnemonic = "lab diesel rule gas student bulb menu option play habit ski result"
mnemonicPrivateKey = bytes.fromhex("1fa9d5e22aa39d264c7c939f99b47696cf534bead88e4ca81da767b1ed122fa8")
mnemonicPublicKey = bytes.fromhex("6ab3e3c1d727fe72e06a6243a05ee6b1607c162a1696629ac9f19b0c1661d586554cadb17ea9d1ae246f60735f9d0e399c61139d7afef72de28809edb695990e")
mnemonicAddress = "0xe402A6296233F2DfefE35cbC3203802965B4E4d7"
checksumAddresses = [
    "0x21fE266480080535b0CCe687669e5DBe13f42559",
    "0x32F9c01ab1247C9366C8A22B6929eB0A905dBBd1",
    "0x5C102a82543448d75FEe35EdA1Fff7cD24D9D02F",
]
message = "Hello world"
correctSignature = "0x14894951ffca216088cba18b434a31fe88cd706886c5f64e0582711d57757ed6f2ecce39370e9ef5da08db891b88d6966245c5f52ce4144661c0015e9a8e97c467bb0a872d0f298f8ab948b882e7c0cbb8070f1067e8b42e34ada2314ae9df221c"
tx = TransactionBody(
    operation=SetOperation(
        ref="/afan",
        value="HAHA",
        type="SET_VALUE",
    ),
    nonce=10,
    timestamp=123,
    parent_tx_hash="",
)
txDifferent = TransactionBody(
    operation=SetOperation(
        ref="/afan",
        value="HAHA",
        type="SET_VALUE",
    ),
    nonce=10,
    timestamp=1234,
    parent_tx_hash="",
)
v3KeystorePassword = "password"
v3KeystoreKDFList = ["scrypt", "pbkdf2"]
v3KeystoreCipherList = ["aes-128-ecb", "aes-128-cbc", "aes128", "aes-128-cfb", "aes-128-cfb8", "aes-128-ofb", "aes-128-ctr"]
v3KeystoreJSONList = [
    '{"version":3,"id":"036b69a2-e265-4629-8228-9fa50e6cfc83","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"d5f30deaaef26536cfa032847ad85b09c7a4e196ef63d958c5f07c2cd492427b61b1db392e34b6a48323df4c63de510b","cipherparams":{"iv":"7f0b94879355a1ad5b0fe2f01505d6a6"},"cipher":"aes-128-cbc","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"869052b90a88af78d8957d857bce751dc497843a5510ecc82060e7c9df96257e","n":262144,"r":8,"p":1},"mac":"54769926fa51577e2f70f30b9665a07bbcf049c0c2d46509c976d97d408e3795"}}',
    '{"version":3,"id":"6cada97a-4b22-4846-a272-89035c027c4f","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"03067fe2bab917fdf54c49f4c155c2ecb21ff27c7883cf88c637132fa43256c528b3f80a8548147f998c210ed483f7bf","cipherparams":{"iv":"4f289baf793101fd10779aa696bb7597"},"cipher":"aes128","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"25661c1cd634d8ae925232763c7d8b3ac82de2729a6570083780ee0c1c59c44d","n":262144,"r":8,"p":1},"mac":"a04a7145044e175b4c5455a8d26b729e4bfe94505dad3d43216ec35a7ac4abbb"}}',
    '{"version":3,"id":"68b26290-dad4-4316-8aa4-f8646c48e95a","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"114bfe8830db8ac40f452fcfc1c258a93dc49db0b10ba8bbd1fc2b9f3e497a25","cipherparams":{"iv":"01f7bad750cc87c2caab2c349b7522fc"},"cipher":"aes-128-cfb","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"81754707b6bf4c353835cba51aacebed90575f8d166d368d4b544f2585fad433","n":262144,"r":8,"p":1},"mac":"3f263fb59cc607c1523efb005bfef096c053a0b0eb3a219d3215477c68206518"}}',
    '{"version":3,"id":"d89885da-8706-455e-ac58-8c0d59532294","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"5e60a23391eeb56b0013a2b3b0dbef67afaf3edb67886855ec6ae623df497312","cipherparams":{"iv":"7ba8e4e0a265236ba34c0c1280e1b8fc"},"cipher":"aes-128-cfb8","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"731a885adad7157c59c30442f9b401b38462ced988f68204b95977a19d9e33cc","n":262144,"r":8,"p":1},"mac":"5fd8e1538d5273ec4941c71a2d7560f2f144f9f7daf5324d2b1ae906da0da373"}}',
    '{"version":3,"id":"930f508f-ac94-4aee-ae1e-e3f7770c4d19","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"14cc2bb2c0c6d66719898745a7e38cb04135f4fc4d7230431fbaf9486f7beff8","cipherparams":{"iv":"06b87f85e1322240b4cbf5706892324c"},"cipher":"aes-128-ofb","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"31fbaa4abd3d56d3f0d817d676be72023a369237af9aa9171344fc3f3506e97f","n":262144,"r":8,"p":1},"mac":"5700a527f864d33bbba505506db45d697e7ad2033f6015d9718f58a4a55d1c77"}}',
    '{"version":3,"id":"7fc2b69c-5589-4e3d-8b00-005116d0313f","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"74633f0c4c573a732b779df0f26ef7b6f6b1d9a80e259f4ff2a6d4d89ba38dbb","cipherparams":{"iv":"cb02dc99e568473ff970ed4fe29c9831"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"16ae5fb31bb38f0d19bd2099d4c3fc0580f8bfe5b9e77f63ec7ebd5642fa6be7","n":262144,"r":8,"p":1},"mac":"faf27bebb19b3ec02ec199181573e8995da8fec97101969e51d6ae2e632d2be2"}}',
]
v3KeystoreFixedUUID = bytes.fromhex("5a548cede1e3f133f2d11b1ef141ef6c")
v3KeystoreFixedIV = bytes.fromhex("4b45d276487b197fafaa81b7037a6268")
v3KeystoreFixedSalt = bytes.fromhex("0445842268ad439d95bc3b44e2cc460333b3ef37f7de775e1e5cad702eebd83c")
v3KeystoreFixedJSON = '{"version":3,"id":"5a548ced-e1e3-4133-b2d1-1b1ef141ef6c","address":"cacd898dbaedbd9037acd25b82417587e972838d","crypto":{"ciphertext":"116c8f26da9f4a5fad7e0f1e039273dbfc3bdfa0adc9342af4cd3bd8a22bcc3d","cipherparams":{"iv":"4b45d276487b197fafaa81b7037a6268"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"0445842268ad439d95bc3b44e2cc460333b3ef37f7de775e1e5cad702eebd83c","n":262144,"r":8,"p":1},"mac":"7cdddc92fe290b26f08ef7031fb8fade154774e4a5ea799d145b158419159add"}}'

ephemPrivateKey = bytes.fromhex("51df6a6e250f9cbb083f319104f2ef8f4093b4851a5a46c0cbd6d00a19bf5078")
encrypted = ECIESEncrypted(
    iv=bytes.fromhex("cbf51904342a81d80a767dca8f5d7399"),
    ephemPublicKey=bytes.fromhex("043a25edc1f59d665ded8a875e7a6d4cf31e4fddc97021b576f8389fa920729cc8d6528a07721102cc43496a14da2a4d7907fd32d57058ab6726b2aea617215106"),
    ciphertext=bytes.fromhex("e71bb030fb2956dff3cb89637352f189"),
    mac=bytes.fromhex("53031981f5f6631ddba5ef6f5a050a1dedb4975b2de2ecc1beaf3e3953582d78"),
)
