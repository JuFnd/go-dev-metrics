package configs

import (
	"flag"
	"os"

	"gopkg.in/yaml.v2"
)

type DbDsnCfg struct {
	User          string `yaml:"user"`
	DbName        string `yaml:"dbname"`
	Password      string `yaml:"password"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	Sslmode       string `yaml:"sslmode"`
	MaxOpenConns  int    `yaml:"max_open_conns"`
	Timer         uint32 `yaml:"timer"`
	Films_db      string `yaml:"films_db"`
	Genres_db     string `yaml:"genres_db"`
	Crew_db       string `yaml:"crew_db"`
	Profession_db string `yaml:"profession_db"`
	ServerAdress  string `yaml:"server_adress"`
}

type CommentCfg struct {
	User         string `yaml:"user"`
	DbName       string `yaml:"dbname"`
	Password     string `yaml:"password"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Sslmode      string `yaml:"sslmode"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	Timer        uint32 `yaml:"timer"`
	Comments_db  string `yaml:"comment_db"`
	ServerAdress string `yaml:"server_adress"`
}

type DbRedisCfg struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	DbNumber int    `yaml:"db"`
	Timer    int    `yaml:"timer"`
}

func ReadCsrfRedisConfig() (*DbRedisCfg, error) {
	var path string
	flag.StringVar(&path, "config_path", "../../configs/db_csrf.yaml", "Путь к конфигу")

	csrfConfig := DbRedisCfg{}
	csrfFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(csrfFile, &csrfConfig)
	if err != nil {
		return nil, err
	}

	return &csrfConfig, nil
}

func ReadSessionRedisConfig() (*DbRedisCfg, error) {
	sessionConfig := DbRedisCfg{}
	sessionFile, err := os.ReadFile("../../configs/db_session.yaml")
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(sessionFile, &sessionConfig)
	if err != nil {
		return nil, err
	}

	return &sessionConfig, nil
}

func ReadConfig() (*DbDsnCfg, error) {
	dsnConfig := DbDsnCfg{}
	dsnFile, err := os.ReadFile("../../configs/db_dsn.yaml")
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(dsnFile, &dsnConfig)
	if err != nil {
		return nil, err
	}

	return &dsnConfig, nil
}

func ReadFilmConfig() (*DbDsnCfg, error) {
	var path string
	flag.StringVar(&path, "films_config_path", "../../configs/db_film_dsn.yaml", "Путь к конфигу фильмов")

	dsnConfig := DbDsnCfg{}
	dsnFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(dsnFile, &dsnConfig)
	if err != nil {
		return nil, err
	}

	return &dsnConfig, nil
}

func ReadCommentConfig() (*CommentCfg, error) {
	var path string
	flag.StringVar(&path, "comments_config_path", "../../configs/db_comment_dsn.yaml", "Путь к конфигу комментов")

	dsnConfig := CommentCfg{}
	dsnFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(dsnFile, &dsnConfig)
	if err != nil {
		return nil, err
	}

	return &dsnConfig, nil
}
