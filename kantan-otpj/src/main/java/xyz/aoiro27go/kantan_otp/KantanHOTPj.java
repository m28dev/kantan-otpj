package xyz.aoiro27go.kantan_otp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KantanHOTPj {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

		/* Step 1: Generate an HMAC-SHA-1 value */
		SecretKeySpec sk = new SecretKeySpec("12345678901234567890".getBytes(), "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(sk);

		// FIXME: counterが1固定
		byte[] ba = ByteBuffer.allocate(8).putLong(1).array();
		byte[] macBytes = mac.doFinal(ba);

		/* Step 2: Dynamic Truncation */
		// 19番目（最後）の値の下位4bitをオフセットにする
		int offset = macBytes[19] & 0xf;
		// オフセット～オフセット+3の中身を連結、最上位ビットはマスクする
		int binCode = (macBytes[offset] & 0x7f) << 24
				| (macBytes[offset + 1] & 0xff) << 16
				| (macBytes[offset + 2] & 0xff) << 8
				| (macBytes[offset + 3] & 0xff);

		/* Step 3: Compute an HOTP value */
		int otp = binCode % (int) Math.pow(10, 6); // Digit = 6
		System.out.println(otp);
	}

}
