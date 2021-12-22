from ain.types import ECDHEncrypted, SetOperation, TransactionBody

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
ephemPrivateKey=bytes.fromhex("51df6a6e250f9cbb083f319104f2ef8f4093b4851a5a46c0cbd6d00a19bf5078")
encrypted = ECDHEncrypted(
    iv=bytes.fromhex("cbf51904342a81d80a767dca8f5d7399"),
    ephemPublicKey=bytes.fromhex("043a25edc1f59d665ded8a875e7a6d4cf31e4fddc97021b576f8389fa920729cc8d6528a07721102cc43496a14da2a4d7907fd32d57058ab6726b2aea617215106"),
    ciphertext=bytes.fromhex("e71bb030fb2956dff3cb89637352f189"),
    mac=bytes.fromhex("53031981f5f6631ddba5ef6f5a050a1dedb4975b2de2ecc1beaf3e3953582d78"),
)
