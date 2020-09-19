package xyz.aoiro27go.kantan_otp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

public class KantanTOTPj4KeyUri {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

		/* Step 0: https://github.com/google/google-authenticator/wiki/Key-Uri-Format */
		String secret = "JBSWY3DPEHPK3PXP";
		Base32 base32 = new Base32();
		byte[] decodedSecret = base32.decode(secret);

		/* Step 1: Generate an HMAC-SHA-1 value */
		SecretKeySpec sk = new SecretKeySpec(decodedSecret, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(sk);

		long unixTime = Instant.now().getEpochSecond();
		long t0 = 0L;
		int x = 30;
		long t = (long) Math.floor((unixTime - t0) / x);

		byte[] tbytes = ByteBuffer.allocate(8).putLong(t).array();
		byte[] macBytes = mac.doFinal(tbytes);

		/* Step 2: Dynamic Truncation */
		// 19番目（最後）の値の下位4bitをオフセットにする
		int offset = macBytes[19] & 0xf;
		// オフセット～オフセット+3の中身を連結、最上位ビットはマスクする
		int binCode = (macBytes[offset] & 0x7f) << 24
				| (macBytes[offset + 1] & 0xff) << 16
				| (macBytes[offset + 2] & 0xff) << 8
				| (macBytes[offset + 3] & 0xff);

		/* Step 3: Compute an HOTP value */
		int digit = 6;
		int otp = binCode % (int) Math.pow(10, digit);

		String result = Integer.toString(otp);
		while (result.length() < digit) {
			result = "0" + result;
		}

		System.out.println(result);
	}

}
