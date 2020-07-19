class Tomtel(decoded: List<UByte>) {
    private val memory = decoded.toUByteArray()
    private val smallRegisters = mutableMapOf(
        "a" to 0.toUByte(),
        "b" to 0.toUByte(),
        "c" to 0.toUByte(),
        "d" to 0.toUByte(),
        "e" to 0.toUByte(),
        "f" to 0.toUByte()
    )
    private val bigRegisters = mutableMapOf(
        "la" to 0u,
        "lb" to 0u,
        "lc" to 0u,
        "ld" to 0u,
        "ptr" to 0u,
        "pc" to 0u
    )
    var instructionSize = 0u
    val output = mutableListOf<UByte>()

    fun emulate(): List<UByte> {
        loop@ while (true) {
            val nextInstruction = getByteFromMemory(0u).toUInt()

            instructionSize = 1234u
            when (nextInstruction) {
                0xC2u -> doAdd()
                0xE1u -> doAptr()
                0xC1u -> doCmp()
                0x01u -> break@loop
                0x21u -> doJez()
                0x22u -> doJnz()
                0x02u -> doOut()
                0xC3u -> doSub()
                0xC4u -> doXor()
                else -> {
                    if (nextInstruction.and(0b11000111u) == 0b01000000u) {
                        doMvi(nextInstruction)
                    } else {
                        if (nextInstruction.and(0b11000000u) == 0b01000000u) {
                            doMv(nextInstruction)
                        }
                    }
                    if (nextInstruction.and(0b11000111u) == 0b10000000u) {
                        doMvi32(nextInstruction)
                    } else {
                        if (nextInstruction.and(0b11000000u) == 0b10000000u) {
                            doMv32(nextInstruction)
                        }
                    }
                }
            }
            if (instructionSize == 1234u) {
                throw RuntimeException("uh oh")
            }
            bigRegisters["pc"] = bigRegisters["pc"]!! + instructionSize
        }

        return output
    }

    private fun doXor() {
        instructionSize = 1u
        smallRegisters["a"] = (smallRegisters["a"]!!.xor(smallRegisters["b"]!!)).toUByte()
    }

    private fun doSub() {
        instructionSize = 1u
        smallRegisters["a"] = (smallRegisters["a"]!! - smallRegisters["b"]!!).toUByte()
    }

    private fun doOut() {
        instructionSize = 1u
        output.add(smallRegisters["a"]!!)
    }

    private fun doMvi32(instruction: UInt) {
        instructionSize = 5u
        val destName = getFirstBigRegister(instruction)
        val value = getIntFromMemory(1u)
        bigRegisters[destName] = value
        if (destName == "pc") {
            instructionSize = 0u
        }
    }

    private fun doMvi(instruction: UInt) {
        instructionSize = 2u
        val destName = getFirstSmallRegister(instruction)
        val value = getByteFromMemory(1u)
        if (destName == "ptr+c") {
            memory[(bigRegisters["ptr"]!! + smallRegisters["c"]!!).toInt()] = value
        } else {
            smallRegisters[destName] = value
        }
    }

    private fun doMv32(instruction: UInt) {
        instructionSize = 1u
        val destName = getFirstBigRegister(instruction)
        val srcName = getSecondBigRegister(instruction)
        val value = if (srcName == "ptr+c") {
            getIntFromPtrC()
        } else {
            bigRegisters[srcName]!!
        }
        bigRegisters[destName] = value
        if (destName == "pc") {
            instructionSize = 0u
        }
    }


    private fun getFirstBigRegister(instruction: UInt): String {
        return getBigRegisterFromNumber(instruction.and(0b00111000u).shr(3))
    }

    private fun getSecondBigRegister(instruction: UInt): String {
        return getBigRegisterFromNumber(instruction.and(0b00000111u))
    }

    private fun getBigRegisterFromNumber(number: UInt): String {
        return when (number) {
            1u -> "la"
            2u -> "lb"
            3u -> "lc"
            4u -> "ld"
            5u -> "ptr"
            6u -> "pc"
            else -> throw RuntimeException("invalid number: " + number)
        }
    }

    private fun doMv(instruction: UInt) {
        instructionSize = 1u
        val destName = getFirstSmallRegister(instruction)
        val srcName = getSecondSmallRegister(instruction)
        val value = if (srcName == "ptr+c") {
            getByteFromPtrC()
        } else {
            smallRegisters[srcName]!!
        }
        if (destName == "ptr+c") {
            memory[(bigRegisters["ptr"]!! + smallRegisters["c"]!!).toInt()] = value
        } else {
            smallRegisters[destName] = value
        }
    }

    private fun getByteFromPtrC(): UByte {
        return memory[(bigRegisters["ptr"]!! + smallRegisters["c"]!!).toInt()]
    }

    private fun getFirstSmallRegister(instruction: UInt): String {
        return getSmallRegisterFromNumber(instruction.and(0b00111000u).shr(3))
    }

    private fun getSecondSmallRegister(instruction: UInt): String {
        return getSmallRegisterFromNumber(instruction.and(0b00000111u))
    }

    private fun getSmallRegisterFromNumber(number: UInt): String {
        return when (number) {
            1u -> "a"
            2u -> "b"
            3u -> "c"
            4u -> "d"
            5u -> "e"
            6u -> "f"
            7u -> "ptr+c"
            else -> throw RuntimeException("invalid number: " + number)
        }
    }

    private fun doJnz() {
        if (smallRegisters["f"] != 0u.toUByte()) {
            instructionSize = 0u
            bigRegisters["pc"] = getIntFromMemory(1u)
        } else {
            instructionSize = 5u
        }
    }

    private fun doJez() {
        if (smallRegisters["f"] == 0u.toUByte()) {
            instructionSize = 0u
            bigRegisters["pc"] = getIntFromMemory(1u)
        } else {
            instructionSize = 5u
        }
    }

    private fun doCmp() {
        instructionSize = 1u
        if (smallRegisters["a"] == smallRegisters["b"]) {
            smallRegisters["f"] = 0u
        } else {
            smallRegisters["f"] = 1u
        }
    }

    private fun doAptr() {
        instructionSize = 2u
        bigRegisters["ptr"] = bigRegisters["ptr"]!! + getByteFromMemory(1u).toUInt()
    }

    private fun doAdd() {
        instructionSize = 1u
        smallRegisters["a"] = (smallRegisters["a"]!! + smallRegisters["b"]!!).toUByte()
    }

    private fun getByteFromMemory(offset: UInt): UByte {
        return memory[(bigRegisters["pc"]!! + offset).toInt()]
    }

    private fun getIntFromMemory(byteOffset: UInt): UInt {
        return getIntFromAddress(bigRegisters["pc"]!! + byteOffset)
    }

    private fun getIntFromPtrC(): UInt {
        return getIntFromAddress(bigRegisters["ptr"]!! + smallRegisters["c"]!!)
    }

    private fun getIntFromAddress(address: UInt): UInt {
        var int = 0u
        for (i in address + 3u downTo address) {
            int = int.shl(8).or(memory[i.toInt()].toUInt())
        }
        return int
    }
}
