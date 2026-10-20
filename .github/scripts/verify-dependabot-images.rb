#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

repo_root = File.expand_path("../..", __dir__)
config_path = File.join(repo_root, ".github", "dependabot.yml")
config = YAML.safe_load(File.read(config_path), aliases: true)

docker_updates = config.fetch("updates").select do |update|
  update["package-ecosystem"] == "docker"
end
abort "dependabot.yml must contain a docker update entry" if docker_updates.empty?

directories = docker_updates.flat_map do |update|
  interval = update.dig("schedule", "interval")
  abort "Docker Dependabot updates must run weekly, got #{interval.inspect}" unless interval == "weekly"

  update.fetch("directories", [update.fetch("directory", nil)])
end.compact.uniq

def dockerfile_for(repo_root, directory)
  relative = directory.delete_prefix("/")
  File.join(repo_root, relative, "Dockerfile")
end

managed_files = directories.map { |directory| dockerfile_for(repo_root, directory) }
missing_manifests = managed_files.reject { |path| File.file?(path) }
unless missing_manifests.empty?
  abort "Dependabot Docker directories without a Dockerfile: #{missing_manifests.map { |path| path.delete_prefix(repo_root + "/") }.join(", ")}"
end

def base_images(path)
  aliases = []
  images = []

  File.foreach(path) do |line|
    tokens = line.strip.split
    next unless tokens.first&.upcase == "FROM"

    image = tokens.drop(1).drop_while { |token| token.start_with?("--") }.first
    abort "Cannot parse FROM instruction in #{path}: #{line.strip}" unless image
    abort "Variable-based base image is not Dependabot-trackable in #{path}: #{image}" if image.include?("$")

    images << image unless image == "scratch" || aliases.include?(image)
    as_index = tokens.index { |token| token.casecmp("AS").zero? }
    aliases << tokens[as_index + 1] if as_index
  end

  images.uniq
end

runtime_files = Dir.glob(File.join(repo_root, "Dockerfile*")).select { |path| File.file?(path) }
runtime_images = runtime_files.flat_map { |path| base_images(path) }.uniq
managed_images = managed_files.flat_map { |path| base_images(path) }.uniq
unmanaged_images = runtime_images - managed_images

unless unmanaged_images.empty?
  abort "Runtime base images missing from Dependabot-managed Dockerfiles: #{unmanaged_images.join(", ")}"
end

puts "Dependabot tracks all runtime base images: #{runtime_images.sort.join(", ")}"
