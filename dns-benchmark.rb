class DnsBenchmark < Formula
  desc "DNS benchmark tool that tests DNS resolver performance across multiple protocols"
  homepage "https://github.com/taihen/dns-benchmark"
  url "https://github.com/taihen/dns-benchmark/archive/v1.3.0.tar.gz"
  sha256 "" # This will be filled in by brew audit --new-formula
  license "MIT"
  head "https://github.com/taihen/dns-benchmark.git", branch: "main"

  depends_on "go" => :build

  def install
    ENV["CGO_ENABLED"] = "0"
    system "go", "build", "-ldflags", "-s -w -X main.version=#{version}", "-o", "dns-benchmark", "./cmd"
    bin.install "dns-benchmark"
  end

  test do
    assert_match "dns-benchmark", shell_output("#{bin}/dns-benchmark --version")
  end
end
