use clap::{Arg, ArgAction, Command, ValueEnum};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Language {
    #[default]
    #[value(name = "en")]
    English,
    #[value(name = "ru")]
    Russian,
}

impl Language {
    pub fn select(args: &[std::ffi::OsString]) -> Self {
        let mut selected = std::env::var("DICH_LANG")
            .ok()
            .map(|value| Self::from_name(&value))
            .unwrap_or_default();
        let mut args = args.iter().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--" {
                break;
            }
            if arg == "--lang" {
                if let Some(value) = args.next().and_then(|value| value.to_str()) {
                    selected = Self::from_name(value);
                }
            } else if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("--lang=")) {
                selected = Self::from_name(value);
            }
        }
        selected
    }

    fn from_name(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "ru" => Self::Russian,
            _ => Self::English,
        }
    }
}

const RU_HELP_TEMPLATE: &str =
    "{before-help}{about-with-newline}\nИспользование: {usage}\n\n{all-args}{after-help}";

pub fn localize_command(mut command: Command, language: Language) -> Command {
    if language == Language::English {
        return command;
    }

    let name = command.get_name().to_owned();
    if let Some(about) = command_about_ru(&name) {
        command = command.about(about);
    }
    if name == "dich" {
        command = command.disable_version_flag(true).arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help("Показать версию"),
        );
    }
    command = command
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help("Показать эту справку")
                .help_heading("Параметры"),
        )
        .help_template(RU_HELP_TEMPLATE)
        .subcommand_help_heading("Команды");

    for (id, help) in argument_help_ru(&name) {
        command = command.mut_arg(id, |arg| arg.help(help).help_heading("Параметры"));
    }

    for subcommand in command.get_subcommands_mut() {
        let localized = localize_command(subcommand.clone(), language);
        *subcommand = localized;
    }
    command
}

fn command_about_ru(name: &str) -> Option<&'static str> {
    Some(match name {
        "dich" => "Экспериментальное версионное хранилище пакетов для Debian и Ubuntu",
        "update" => "Обновить проверенные метаданные пакетов",
        "search" => "Найти пакеты в локальном кэше",
        "show" => "Показать сведения о пакете из кэша",
        "versions" => "Показать версии пакета из кэша",
        "plan" => "Составить экспериментальный план зависимостей без установки",
        "fetch" => "Загрузить точный пакет в проверенный кэш; не устанавливает его",
        "inspect" => "Проверить локальный архив Debian без извлечения и запуска сценариев",
        "install" => "Выбрать поддерживаемую DSO-цепочку в профиле",
        "remove" => "Отключить поколение профиля",
        "rollback" => "Переключить профиль на предыдущее поколение",
        "store" => "Проверить локальные объекты хранилища",
        "ls" => "Показать записи хранилища без проверки содержимого объектов",
        "verify" => "Сверить объект с локальными метаданными",
        "profile" => "Показать поколения профилей",
        "list" => "Показать элементы списка",
        "sources" => "Управлять настроенными источниками пакетов",
        "setup" => "Создать настройки официального источника Debian или Ubuntu",
        "gc" => "Найти и удалить недостижимые объекты хранилища",
        _ => return None,
    })
}

fn argument_help_ru(command: &str) -> &'static [(&'static str, &'static str)] {
    match command {
        "dich" => &[
            ("lang", "Язык интерфейса справки и человекочитаемых ошибок"),
            ("config", "Путь к политике доверенных источников"),
            ("cache", "Защищённый каталог кэша"),
            ("store_dir", "Защищённый каталог хранилища"),
            ("rootless", "Принудительно включить пользовательский режим"),
            ("system", "Принудительно включить системные каталоги"),
            ("offline", "Запретить сеть и использовать только кэш"),
            (
                "max_bandwidth",
                "Максимальная скорость загрузки в байтах в секунду; 0 — без ограничения",
            ),
            (
                "https_proxy",
                "Явный HTTP CONNECT-прокси без учётных данных; проверка TLS сохраняется",
            ),
            (
                "max_age_seconds",
                "Максимальный возраст подписанных метаданных Release в секундах (по умолчанию 86400)",
            ),
            (
                "allow_missing_valid_until",
                "Устаревший совместимый флаг: допускает отсутствие Valid-Until при ограничении возраста",
            ),
            (
                "require_valid_until",
                "Требовать Valid-Until в подписанных метаданных Release",
            ),
            ("json", "Выводить версионированные JSON-ответы и ошибки"),
            ("log_level", "Уровень структурированного журнала"),
            ("progress", "Показывать ход операции в stderr"),
        ],
        "search" => &[("query", "Строка поиска")],
        "show" | "versions" => &[("package", "Имя пакета")],
        "install" => &[
            ("package", "Имя пакета"),
            ("profile", "Имя профиля"),
            ("exact_version", "Точная версия пакета Debian"),
            ("yes", "Подтвердить операцию"),
        ],
        "remove" => &[
            ("package", "Имя пакета"),
            ("profile", "Имя профиля"),
            ("yes", "Подтвердить операцию"),
        ],
        "plan" => &[
            ("package", "Имя пакета"),
            ("distribution", "Дистрибутив: debian или ubuntu"),
            ("suite", "Неизменяемая метка выпуска"),
            ("architecture", "Целевая архитектура"),
        ],
        "fetch" => &[
            ("package", "Имя пакета"),
            ("exact_version", "Точная версия Debian"),
            ("component", "Компонент настроенного источника"),
            ("max_bytes", "Предельный размер загрузки"),
            (
                "publish_tree",
                "Опубликовать безопасно извлечённое дерево без активации",
            ),
        ],
        "inspect" => &[
            ("file", "Путь к архиву .deb"),
            ("with", "Дополнительный архив для явной DSO-цепочки"),
        ],
        "rollback" => &[
            ("profile", "Имя профиля"),
            ("yes", "Подтвердить переключение профиля"),
        ],
        "verify" => &[
            ("id", "Идентификатор объекта"),
            ("kind", "Тип объекта: archive или tree"),
        ],
        "gc" => &[
            (
                "dry_run",
                "Показать кандидатов на удаление без изменений (по умолчанию)",
            ),
            ("execute", "Удалить недостижимые деревья и их метаданные"),
        ],
        _ => &[],
    }
}

pub fn error_message_ru(code: &str) -> Option<&'static str> {
    Some(match code {
        "invalid_arguments" => "неверные аргументы командной строки",
        "unsupported" | "compatibility_rejected" => {
            "пакет не соответствует поддерживаемой политике DSO"
        }
        "unsatisfiable" => "не удалось разрешить зависимости пакета",
        "integrity_rejected" | "verification_failed" | "signature_failed" | "tampered_metadata" => {
            "проверка целостности или подписи не пройдена"
        }
        "permission_denied" => "недостаточно прав доступа",
        "offline_mode" => "необходимый артефакт отсутствует в кэше, а указан режим --offline",
        "store_open_failed" => "не удалось безопасно открыть хранилище",
        "source_load_failed" => "не удалось загрузить политику источников",
        "cache_unavailable" | "cache_open_failed" => "кэш недоступен",
        "package_not_found" => "пакет не найден",
        "profile_missing" => "профиль не найден",
        "profile_conflict" => "профиль уже выбирает другой корневой пакет",
        "rollback_unavailable" => "предыдущее поколение профиля недоступно",
        "unsupported_platform" => "операции требуют Linux с поддержкой openat2",
        "missing_age" | "freshness_policy_required" => {
            "задайте --max-age-seconds для проверки свежести подписанных метаданных Release"
        }
        "missing_proxy" => "задайте --https-proxy <http://host:port> для настройки прокси",
        "disk_space_insufficient" => "недостаточно свободного места на целевой файловой системе",
        "default_source_unsupported" => {
            "для этой системы нет поддерживаемой настройки источника по умолчанию"
        }
        "default_keyring_unavailable" => "системный ключ архива отсутствует или небезопасен",
        "config_exists" => "файл конфигурации уже существует и не был изменён",
        _ => return None,
    })
}

pub fn error_hint_ru(code: &str) -> Option<&'static str> {
    Some(match code {
        "unsupported" | "compatibility_rejected" => {
            "Запустите 'dich inspect <deb>', чтобы изучить ограничения совместимости."
        }
        "store_open_failed" => "Проверьте путь хранилища через --store-dir или права доступа.",
        "source_load_failed" => "Проверьте файл политики источников через --config.",
        "cache_unavailable" | "cache_open_failed" => {
            "Проверьте путь кэша через --cache или выполните 'dich update'."
        }
        "permission_denied" => {
            "Для системных путей запустите с нужными правами или используйте --rootless."
        }
        "offline_mode" => {
            "Подключитесь к сети для загрузки или проверьте, что пакет уже находится в кэше."
        }
        "disk_space_insufficient" => "Освободите место или сначала проверьте отчёт 'dich gc'.",
        "unsatisfiable" => "Выполните 'dich search <package>', чтобы посмотреть доступные версии.",
        "profile_missing" => "Выполните 'dich profile list', чтобы посмотреть профили.",
        "rollback_unavailable" => "У профиля нет сохранённого предыдущего поколения.",
        "missing_age" | "freshness_policy_required" => {
            "Явно задайте максимальный возраст метаданных через --max-age-seconds."
        }
        "missing_proxy" => "Задайте --https-proxy <http://host:port>.",
        "invalid_arguments" => "Выполните 'dich --help' или 'dich <команда> --help'.",
        "unsupported_platform" => "Для операций профилей требуется Linux с поддержкой openat2.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;

    #[test]
    fn russian_help_is_localized_and_english_stays_default() {
        let russian = Cli::command_for_language(Language::Russian)
            .render_long_help()
            .to_string();
        assert!(russian.contains("Использование:"));
        assert!(russian.contains("Обновить проверенные метаданные пакетов"));
        assert!(russian.contains("Язык интерфейса"));
        assert!(russian.contains("Показать эту справку"));
        assert!(russian.contains("Показать версию"));
        assert!(!russian.contains("Print this message"));
        assert!(!russian.contains("Print version"));

        let english = Cli::command_for_language(Language::English)
            .render_long_help()
            .to_string();
        assert!(english.contains("Usage:"));
        assert!(english.contains("Refresh authenticated package metadata"));
    }

    #[test]
    fn nested_help_is_localized() {
        let error = Cli::command_for_language(Language::Russian)
            .try_get_matches_from(["dich", "fetch", "--help"])
            .expect_err("help exits parsing");
        assert!(error.to_string().contains("Загрузить точный пакет"));
        assert!(error.to_string().contains("Точная версия Debian"));
    }

    #[test]
    fn human_errors_are_translated_but_json_contract_stays_english() {
        let error = crate::CliError {
            code: "unsupported",
            message: "package is outside the supported DSO policy",
            trace: Vec::new(),
        };
        let human = error.render_for(false, Language::Russian);
        assert!(human.contains("dich: ошибка:"));
        assert!(human.contains("пакет не соответствует поддерживаемой политике DSO"));

        let json = error.render_for(true, Language::Russian);
        assert!(json.contains("package is outside the supported DSO policy"));
        assert!(!json.contains("не соответствует"));
    }
}
