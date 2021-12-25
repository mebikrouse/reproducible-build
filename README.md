# Mach-O Utility

В данном репозитории вы можете видеть пример утилиты, которая позволяет считывать и манипулировать Mach-O файлами.

Для компиляции используйте следующую команду:
`clang -lc mach-o-utility.c -o mach-o-utility`

Использование утилиты:
- `mach-o-utility --is-fat input_file`
- `mach-o-utility --contains input_file seg_name sect_name`
- `mach-o-utility --extract seg_name sect_name input_file output_file`
- `mach-o-utility --validate input_file_a input_file_b`

Опции:
- `--is-fat` - проверяет, является ли Mach-O файл universal binary.
- `--contains` - проверяет, содержит ли Mach-O файл секцию __sect_name__ в сегменте __seg_name__.
- `--extract` - извлекает из Mach-O файла секцию __sect_name__ сегмента __seg_name__.
- `--validate` - сравнивает два Mach-O файла, стирая из них загрузочные команды `LC_ID_DYLIB`, `LC_UUID`, а также секцию `__swift_modhash` сегмента `__LLVM`.