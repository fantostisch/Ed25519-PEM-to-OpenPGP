package nl.na1.PEMToOpenPGP

import ResearchUtils
import org.bouncycastle.math.ec.custom.djb.Curve25519
import org.bouncycastle.math.ec.rfc7748.X25519Field
import org.junit.Test
import java.math.BigInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class ResearchTest {

    // Copied from Ed25519.java
    val xBaseArray = intArrayOf(
        0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
        0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D
    )

    // Copied from Ed25519.java
    val yBaseArray = intArrayOf(
        0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
        0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC
    )

    @Test
    fun bigIntegerConversionBaseX() {
        val xBigActual = ResearchUtils.fieldNumberToBigInt(xBaseArray)
        assertEquals(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202",
            xBigActual.toString(10)
        )
        assertContentEquals(xBaseArray, ResearchUtils.bigIntToFieldNumber(xBigActual))
    }

    @Test
    fun bigIntegerConversionY() {
        // Copied from Ed25519Field.java
        val yBigActual = ResearchUtils.fieldNumberToBigInt(yBaseArray)
        assertEquals(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960",
            yBigActual.toString(10)
        )
        assertContentEquals(yBaseArray, ResearchUtils.bigIntToFieldNumber(yBigActual))
    }

    @Test
    fun bigIntegerConversionBaseSQRT_M1() {
        // Copied from Ed25519.java
        val SQRT_M1 = intArrayOf(
            0x020EA0B0, 0x0386C9D2, 0x00478C4E, 0x0035697F, 0x005E8630,
            0x01FBD7A7, 0x0340264F, 0x01F0B2B4, 0x00027E0E, 0x00570649
        )
        val SQRT_M1_BigIntActual = ResearchUtils.fieldNumberToBigInt(SQRT_M1)
        assertEquals(
            "19681161376707505956807079304988542015446066515923890162744021073123829784752",
            SQRT_M1_BigIntActual.toString(10)
        )
        assertContentEquals(
            SQRT_M1,
            ResearchUtils.bigIntToFieldNumber(SQRT_M1_BigIntActual)
        )
    }

    @Test
    fun scaling() {
        // https://math.stackexchange.com/q/1392277
        val vUnscaled =
            ResearchUtils.bigIntToFieldNumber(BigInteger("46155036877857898950720737868668298259344786430663990124372813544693780678454"))
        val scaled = X25519Field.create()
        ResearchUtils.scale(vUnscaled, scaled)
        assertEquals(
            "14781619447589544791020593568409986887264606134616475288964881837755586237401",
            ResearchUtils.fieldNumberToBigInt(scaled).toString()
        )
    }

    @Test
    fun edwardsToMontgomery() {
        val u = X25519Field.create()
        val v = X25519Field.create()
        ResearchUtils.twistedEdwardsToMontgomery(xBaseArray, yBaseArray, u, v)
        val uBigNum = ResearchUtils.fieldNumberToBigInt(u)
        assertEquals(9, uBigNum.longValueExact())
        val vBigNum = ResearchUtils.fieldNumberToBigInt(v)
        assertEquals(
            "14781619447589544791020593568409986887264606134616475288964881837755586237401",
            vBigNum.toString(10)
        )
    }

    @Test
    // https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html#rfc.appendix.E.3
    fun montgomeryToWeierstrass() {
        val xMont = BigInteger.valueOf(9)
        val yMont =
            BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401")

        val xWeierstrassIntArray = X25519Field.create()
        ResearchUtils.montgomeryToWeierstrassX(
            ResearchUtils.bigIntToFieldNumber(xMont),
            xWeierstrassIntArray
        )
        val xWeierstrass = ResearchUtils.fieldNumberToBigInt(xWeierstrassIntArray)

        val yWeierstrassIntArray = X25519Field.create()
        ResearchUtils.montgomeryToWeierstrassY(
            ResearchUtils.bigIntToFieldNumber(yMont),
            yWeierstrassIntArray
        )
        val yWeierstrass = ResearchUtils.fieldNumberToBigInt(yWeierstrassIntArray)

        assertEquals(
            "19298681539552699237261830834781317975544997444273427339909597334652188435546",
            xWeierstrass.toString()

        )
        assertEquals(
            "14781619447589544791020593568409986887264606134616475288964881837755586237401",
            yWeierstrass.toString()
        )

        val curve = Curve25519()
        val point = curve.createPoint(xWeierstrass, yWeierstrass)
        assertEquals(true, point.isValid)
    }
}
