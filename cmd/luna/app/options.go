package app

// Options for luna controller
type Options struct {
	DSN string `yaml:"dsn" validate:"required"`
}
