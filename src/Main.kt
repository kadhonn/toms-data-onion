import java.io.File
import java.nio.file.Files
import java.util.stream.Collectors
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.experimental.xor

fun main() {
    doFile("layer0"){
        String(ascii85Decode(it).toByteArray())
    }
    doFile("layer1"){
        String(flipAndShiftBytes(ascii85Decode(it)).toByteArray())
    }
}

fun flipAndShiftBytes(decoded: List<Byte>): List<Byte> {
    return decoded.map {
        var byte = it.xor(0b01010101)
        val lastBit = byte.and(0b00000001)
        byte = byte.toInt().and(0xff).shr(1).toByte()
        byte = byte.or(lastBit)
        byte
    }
}

private fun doFile(file: String, layer: (String) -> String) {
    val input = Files.lines(File("resources/$file.in").toPath()).collect(Collectors.joining(""))
    val result = layer(input)
    Files.writeString(File("resources/$file.out").toPath(), result)
}

fun ascii85Decode(input: String): List<Byte> {
    val regex = """\<\~(.*)\~\>""".toRegex()
    val matchResult = regex.find(input)
    val (stuff) = matchResult!!.destructured

    val chars = stuff.toCharArray()
    val outBytes = mutableListOf<Byte>()

    var group = 0L
    var groupCount = 0
    var i = 0
    while (i < chars.size) {
        val char = chars[i]
        if (char.isWhitespace()) {
            continue
        }
        if (char == 'z') {
            for (j in 1..4) {
                outBytes.add(0)
            }
        } else {
            val binaryPart = char - 33
            group = group * 85 + binaryPart.toLong()
            groupCount++
            if (groupCount == 5) {
                splitLong(outBytes, group)
                group = 0
                groupCount = 0
            }
        }
        i++
    }
    if (groupCount != 0) {
        for (j in 1..(5 - groupCount)) {
            group = group * 85 + ('u' - 33).toLong()
        }
        splitLong(outBytes, group)
        for (j in 1..(5 - groupCount)) {
            outBytes.removeAt(outBytes.size - 1)
        }
    }

    return outBytes
}

fun splitLong(outBytes: MutableList<Byte>, group: Long) {
    var groupToModify = group
    val bytes = mutableListOf<Byte>()
    for (j in 1..4) {
        bytes.add((groupToModify % 256).toByte())
        groupToModify /= 256
    }
    outBytes.addAll(bytes.reversed())
}
