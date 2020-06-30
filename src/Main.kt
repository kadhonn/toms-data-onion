import java.io.File
import java.nio.file.Files
import java.util.stream.Collectors

fun main() {
    doFile("layer0") {
        String(ascii85Decode(it).map { it.toByte() }.toByteArray())
    }
    doFile("layer1") {
        String(flipAndShiftUBytes(ascii85Decode(it)).map { it.toByte() }.toByteArray())
    }
    doFile("layer2") {
        String(parityChecks(ascii85Decode(it)).map { it.toByte() }.toByteArray())
    }
    doFile("layer3") {
        String(decrypt(ascii85Decode(it)).map { it.toByte() }.toByteArray())
    }
}

fun decrypt(decoded: List<UByte>): List<UByte> {
    val start = "==[ Layer 4/5: Network Traffic ]==="
    return decoded.mapIndexed { index, byte ->
        byte.xor(decoded[index % 32].xor(start.toCharArray()[index % 32].toByte().toUByte()))
    }
}

fun parityChecks(decoded: List<UByte>): List<UByte> {
    val filtered = decoded.filter {
        var byte = it.toInt()
        var count = 0
        for (i in 1..8) {
            count += byte.and(0b1)
            byte = byte.shr(1)
        }
        count % 2 == 0
    }
    val result = mutableListOf<UByte>()
    for (i in filtered.indices step 8) {
        val byte1 = filtered[i].and(0b11111110u).or(filtered[i + 1].toUInt().shr(7).toUByte().and(0b1u))
        val byte2 = filtered[i + 1].toUInt().shl(1).toUByte().and(0b11111100u).or(filtered[i + 2].toUInt().shr(6).toUByte().and(0b11u))
        val byte3 = filtered[i + 2].toUInt().shl(2).toUByte().and(0b11111000u).or(filtered[i + 3].toUInt().shr(5).toUByte().and(0b111u))
        val byte4 = filtered[i + 3].toUInt().shl(3).toUByte().and(0b11110000u).or(filtered[i + 4].toUInt().shr(4).toUByte().and(0b1111u))
        val byte5 = filtered[i + 4].toUInt().shl(4).toUByte().and(0b11100000u).or(filtered[i + 5].toUInt().shr(3).toUByte().and(0b11111u))
        val byte6 = filtered[i + 5].toUInt().shl(5).toUByte().and(0b11000000u).or(filtered[i + 6].toUInt().shr(2).toUByte().and(0b111111u))
        val byte7 = filtered[i + 6].toUInt().shl(6).toUByte().and(0b10000000u).or(filtered[i + 7].toUInt().shr(1).toUByte().and(0b1111111u))
        result.addAll(listOf(byte1, byte2, byte3, byte4, byte5, byte6, byte7))
    }
    return result
}

fun flipAndShiftUBytes(decoded: List<UByte>): List<UByte> {
    return decoded.map {
        var byte = it.xor(0b01010101u)
        val lastBit = byte.and(0b00000001u)
        byte = byte.toUInt().and(0xffu).shr(1).toUByte()
        byte = byte.or(lastBit)
        byte
    }
}

private fun doFile(file: String, layer: (String) -> String) {
    val input = Files.lines(File("resources/$file.in").toPath()).collect(Collectors.joining(""))
    val result = layer(input)
    Files.writeString(File("resources/$file.out").toPath(), result)
}

fun ascii85Decode(input: String): List<UByte> {
    val regex = """\<\~(.*)\~\>""".toRegex()
    val matchResult = regex.find(input)
    val (stuff) = matchResult!!.destructured

    val chars = stuff.toCharArray()
    val outUBytes = mutableListOf<UByte>()

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
                outUBytes.add(0u)
            }
        } else {
            val binaryPart = char - 33
            group = group * 85 + binaryPart.toLong()
            groupCount++
            if (groupCount == 5) {
                splitLong(outUBytes, group)
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
        splitLong(outUBytes, group)
        for (j in 1..(5 - groupCount)) {
            outUBytes.removeAt(outUBytes.size - 1)
        }
    }

    return outUBytes
}

fun splitLong(outUBytes: MutableList<UByte>, group: Long) {
    var groupToModify = group
    val bytes = mutableListOf<UByte>()
    for (j in 1..4) {
        bytes.add((groupToModify % 256).toUByte())
        groupToModify /= 256
    }
    outUBytes.addAll(bytes.reversed())
}
