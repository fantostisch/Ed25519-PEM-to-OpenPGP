import org.bouncycastle.math.ec.rfc7748.X25519Field
import java.math.BigInteger

// Everything in this file is not used by the program
object ResearchUtils {
    /**
     * Calculate the u coordinate on the montgomery curve using the y coordinate from
     * the twisted edwards curve. u = (1+y)/(1-y)
     */
    fun twistedEdwardsToMontgomeryU(y: IntArray, r: IntArray) {
        val n = X25519Field.create(); X25519Field.copy(y, 0, n, 0)
        X25519Field.addOne(n)

        val d = X25519Field.create()
        val one = X25519Field.create(); one[0] = 1;
        X25519Field.sub(one, y, d)

        X25519Field.inv(d, d)
        X25519Field.mul(n, d, r)
        X25519Field.normalize(r)
    }

    /**
     * Calculate the v coordinate on the montgomery curve using the x and y coordinate
     * from the twisted edwards curve. v = (1+y)/((1-y)x)
     */
    fun twistedEdwardsToMontgomeryV(x: IntArray, y: IntArray, r: IntArray) {
        val n = X25519Field.create(); X25519Field.copy(y, 0, n, 0)
        X25519Field.addOne(n)

        val d = X25519Field.create()
        val one = X25519Field.create(); one[0] = 1;
        X25519Field.sub(one, y, d)
        X25519Field.mul(d, x, d)

        X25519Field.inv(d, d)
        X25519Field.mul(n, d, r)
        X25519Field.normalize(r)
        scale(r, r)
    }

    // x = ((x+A/3)/B)
    fun montgomeryToWeierstrassX(x: IntArray, r: IntArray) {
        X25519Field.copy(x, 0, r, 0)

        val a = X25519Field.create(); a[0] = 486662;

        val inv3 = X25519Field.create(); inv3[0] = 3;
        X25519Field.inv(inv3, inv3)

        X25519Field.mul(a, inv3, r)

        val bInv = X25519Field.create(); bInv[0] = 1;
        X25519Field.inv(bInv, bInv)

        X25519Field.add(x, r, r)

        X25519Field.mul(r, bInv, r)
        X25519Field.normalize(r)
    }

    // y = y/B
    fun montgomeryToWeierstrassY(x: IntArray, r: IntArray) {
        val bInv = X25519Field.create(); bInv[0] = 1;
        X25519Field.inv(bInv, bInv)

        X25519Field.mul(x, bInv, r)
    }

    fun fieldNumberToBigInt(x: IntArray): BigInteger {
        val tmp = ByteArray(32)
        X25519Field.encode(x, tmp, 0)
        return BigInteger(1, tmp.reversedArray())
    }

    fun bigIntToFieldNumber(b: BigInteger): IntArray {
        val tmp = b.toByteArray().reversedArray().copyOf(32)
        val r = IntArray(10)
        X25519Field.decode(tmp, 0, r)
        return r
    }

    fun scale(x: IntArray, r: IntArray) {
        // https://math.stackexchange.com/q/1392277
        val scalingFactor =
            bigIntToFieldNumber(BigInteger("16416487832636737118837039172820900612695230415163812779824790760673067034857"))
        val invScalingFactor = X25519Field.create()
        X25519Field.inv(scalingFactor, invScalingFactor)
        X25519Field.mul(x, invScalingFactor, r)
        X25519Field.normalize(r)
    }
}
