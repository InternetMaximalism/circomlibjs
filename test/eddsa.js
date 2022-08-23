import chai from "chai";
import { Scalar } from "ffjavascript";

const assert = chai.assert;

import buildEddsa from "../src/eddsa.js";

const fromHexString = hexString =>
    new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
    bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');


describe("EdDSA js test", function () {

    let eddsa;
    this.timeout(100000);

    before(async () => {
        eddsa = await buildEddsa();
    });


    it("Sign (using Pedersen) a single 10 bytes from 0 to 9", () => {
        const F = eddsa.babyJub.F;
        const msgBuf = fromHexString("00010203040506070809");

        const prvKey = fromHexString("0001020304050607080900010203040506070809000102030405060708090001");

        const pubKey = eddsa.prv2pub(prvKey);

        assert(F.eq(pubKey[0], F.e("13277427435165878497778222415993513565335242147425444199013288855685581939618")));
        assert(F.eq(pubKey[1], F.e("13622229784656158136036771217484571176836296686641868549125388198837476602820")));

        const pPubKey = eddsa.babyJub.packPoint(pubKey);

        const signature = eddsa.signPedersen(prvKey, msgBuf);
        // console.log(F.toString(signature.R8[0]));
        assert(F.eq(signature.R8[0], F.e("21253904451576600568378459528205653033385900307028841334532552830614710476912")));
        // console.log(F.toString(signature.R8[1]));
        assert(F.eq(signature.R8[1], F.e("20125634407542493427571099944365246191501563803226486072348038614369379124499")));
        // console.log(Scalar.toString(signature.S));
        assert(Scalar.eq(signature.S, Scalar.e("2129243915978267980511515511350111723623685317644064470882297086073041379651")));

        const pSignature = eddsa.packSignature(signature);

        // console.log(toHexString(pSignature));
        assert.equal(toHexString(pSignature), "" +
            "138501d9e734e73f485269bcdc29a9ef2da3fac2f5c9653761d0364f95b47eac" +
            "43e1a02b56ff3dacfdac040f3e8c2023dc259ba3f6880ca8ad246b4bfe1bb504");

        const uSignature = eddsa.unpackSignature(pSignature);
        assert(eddsa.verifyPedersen(msgBuf, uSignature, pubKey));

    });

    it("Sign (using Mimc7) a single 10 bytes from 0 to 9", () => {
        const F = eddsa.babyJub.F;
        const msgBuf = fromHexString("000102030405060708090000");

        const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(msgBuf, 0));

        //  const prvKey = crypto.randomBytes(32);

        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");

        const pubKey = eddsa.prv2pub(prvKey);

        assert(F.eq(pubKey[0], F.e("13277427435165878497778222415993513565335242147425444199013288855685581939618")));
        assert(F.eq(pubKey[1], F.e("13622229784656158136036771217484571176836296686641868549125388198837476602820")));

        const pPubKey = eddsa.babyJub.packPoint(pubKey);

        const signature = eddsa.signMiMC(prvKey, msg);
        // console.log(F.toString(signature.R8[0]));
        assert(F.eq(signature.R8[0], F.e("11384336176656855268977457483345535180380036354188103142384839473266348197733")));
        // console.log(F.toString(signature.R8[1]));
        assert(F.eq(signature.R8[1], F.e("15383486972088797283337779941324724402501462225528836549661220478783371668959")));
        // console.log(Scalar.toString(signature.S));
        assert(Scalar.eq(signature.S, Scalar.e("2523202440825208709475937830811065542425109372212752003460238913256192595070")));

        const pSignature = eddsa.packSignature(signature);

        // console.log(toHexString(pSignature));
        assert.equal(toHexString(pSignature), "" +
            "dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2" +
            "7ed40dab29bf993c928e789d007387998901a24913d44fddb64b1f21fc149405");

        const uSignature = eddsa.unpackSignature(pSignature);
        assert(eddsa.verifyMiMC(msg, uSignature, pubKey));

    });

    it("Sign (using Poseidon) to F.e(1)", () => {
        const F = eddsa.babyJub.F;
        const msgBuf = fromHexString("0100105c9e139eb220b73f3160b40bcb04d7ffca70f5978e896e506e24ea3330"); // F.e(1)
        console.log("msgBuf:", msgBuf);
        const msgScalar = Scalar.fromRprLE(msgBuf, 0);
        console.log("msgScalar:", msgScalar);
        const msg = F.e(msgScalar);
        console.log("msg:", Buffer.from(msg).toString("hex"));

        //  const prvKey = crypto.randomBytes(32);

        const prvKey = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex");

        const pubKey = eddsa.prvTopub(prvKey);

        // assert(F.eq(pubKey[0], F.e("13277427435165878497778222415993513565335242147425444199013288855685581939618")));
        assert(F.eq(pubKey[1], F.e("0x13c207a69f6e609215e86cc1ff67d860ea5fe371fcf744b3752b7b6f39035ae7")));

        const pPubKey = eddsa.babyJub.packPoint(pubKey);
        assert.equal(Buffer.from(pPubKey).toString("hex"), "e75a03396f7b2b75b344f7fc71e35fea60d867ffc16ce81592606e9fa607c213");

        const signature = eddsa.signPoseidon(prvKey, msg);

        // assert(F.eq(signature.R8[0], F.e("14912433543938312892253433221595649502191805434744400916320858340963708903405")));
        // // console.log(F.toString(signature.R8[1]));
        // assert(F.eq(signature.R8[1], F.e("17858965943805078502965389429364548292533041582201285272843856055529454259328")));
        // // console.log(Scalar.toString(signature.S));
        // assert(Scalar.eq(signature.S, Scalar.e("2064552818548881709952691052207091855126437691923743153565018691634475028895")));

        const pSignature = eddsa.packSignature(signature);

        assert.equal(toHexString(pSignature), "" +
            "aac045b6df200c31faa438cbb51052d9d78259957e9f56f3689bb13c071e0127" +
            "76da91d80dafa2df5e1087ee85c4e84952fb6a92fd726c62281cf0c74944b900");

        const uSignature = eddsa.unpackSignature(pSignature);
        assert(eddsa.verifyPoseidon(msg, uSignature, pubKey));
    });


    it("Sign (using mimcsponge) a single 10 bytes from 0 to 9", () => {
        const F = eddsa.babyJub.F;
        const msgBuf = fromHexString("000102030405060708090000");

        const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(msgBuf, 0));

        //  const prvKey = crypto.randomBytes(32);

        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");

        const pubKey = eddsa.prv2pub(prvKey);

        assert(F.eq(pubKey[0], F.e("13277427435165878497778222415993513565335242147425444199013288855685581939618")));
        assert(F.eq(pubKey[1], F.e("13622229784656158136036771217484571176836296686641868549125388198837476602820")));

        const pPubKey = eddsa.babyJub.packPoint(pubKey);

        const signature = eddsa.signMiMCSponge(prvKey, msg);
        // console.log(F.toString(signature.R8[0]));
        assert(F.eq(signature.R8[0], F.e("11384336176656855268977457483345535180380036354188103142384839473266348197733")));
        // console.log(F.toString(signature.R8[1]));
        assert(F.eq(signature.R8[1], F.e("15383486972088797283337779941324724402501462225528836549661220478783371668959")));
        // console.log(Scalar.toString(signature.S));
        assert(Scalar.eq(signature.S, Scalar.e("1868336918738674306327358602987493427631678603535639134028485964115448322340")));

        const pSignature = eddsa.packSignature(signature);

        // console.log(toHexString(pSignature));
        assert.equal(toHexString(pSignature), "" +
            "dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2" +
            "24599218a1c2e5290bf58b2eec37bfec1395179ed5e817f10f86c9e7f3702104");

        const uSignature = eddsa.unpackSignature(pSignature);
        assert(eddsa.verifyMiMCSponge(msg, uSignature, pubKey));
    });
});
