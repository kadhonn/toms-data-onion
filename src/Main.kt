import java.io.File
import java.nio.file.Files

fun main() {
    Files.lines(File("resources/layer0.txt").toPath()).forEach { println(it) }
}
