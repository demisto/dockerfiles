import argparse
import sys
from pathlib import Path
from sentinel.extractor import get_script_from_file
from sentinel.analyzer import ScriptAnalyzer
from sentinel.reporters import ConsoleReporter, JSONReporter, MarkdownReporter, ExplainReporter
from sentinel.yara_engine import YaraEngine, YaraRuleError


def detect_format_from_extension(file_path: str) -> str:
    """
    Auto-detect output format from file extension.
    
    Args:
        file_path: Path to the output file
        
    Returns:
        Format string: 'json', 'md', or 'console'
    """
    ext = Path(file_path).suffix.lower()
    if ext == '.json':
        return 'json'
    elif ext == '.md':
        return 'md'
    else:
        return 'console'


def select_reporter(format_type: str):
    """
    Select appropriate reporter based on format type.
    
    Args:
        format_type: One of 'console', 'json', or 'md'
        
    Returns:
        Reporter instance
        
    Raises:
        ValueError: If format_type is invalid
    """
    if format_type == 'json':
        return JSONReporter()
    elif format_type == 'md':
        return MarkdownReporter()
    elif format_type == 'console':
        return ConsoleReporter()
    else:
        raise ValueError(f"Invalid format: {format_type}. Must be 'console', 'json', or 'md'.")


def main():
    """
    Script Sentinel CLI entry point.

    Parses command-line arguments and dispatches to appropriate handlers:
    - analyze: Analyze a script file for malicious patterns
    - --list-rules: Display loaded Yara rules and statistics
    - --strict: Enable strict mode for Yara rule validation (with --list-rules)

    Exit codes:
        0: Success
        1: Error (file not found, analysis failed, invalid rules in strict mode)
    """
    parser = argparse.ArgumentParser(
        description="Script Sentinel - A script analysis tool",
        epilog="Examples:\n"
               "  %(prog)s analyze script.ps1                    # Console output to stdout\n"
               "  %(prog)s analyze script.ps1 -o report.json     # JSON output to file\n"
               "  %(prog)s analyze script.ps1 -o report.md       # Markdown output to file\n"
               "  %(prog)s analyze script.ps1 -f json            # JSON output to stdout\n"
               "  %(prog)s analyze script.ps1 -v                 # Show all findings (verbose)\n"
               "  %(prog)s analyze script.ps1 --paranoia-level 2 # Aggressive detection\n"
               "  %(prog)s analyze script.ps1 --enable-llm       # Enable LLM semantic analysis\n"
               "  %(prog)s analyze script.ps1 --enable-llm --llm-model pro  # Use Pro model\n"
               "  %(prog)s analyze script.ps1 -o out.txt -f md   # Markdown to file (explicit format)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    parser.add_argument(
        "--strict",
        action="store_true",
        dest="strict_mode",
        help="Enable strict mode: exit with error on first invalid Yara rule (use with --list-rules)"
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        dest="list_rules",
        help="List all loaded Yara rules and exit"
    )
    parser.add_argument(
        "--expected-public",
        type=int,
        dest="expected_public",
        metavar="N",
        help="Expected number of public Yara rules (CI validation, use with --list-rules)"
    )
    parser.add_argument(
        "--expected-custom",
        type=int,
        dest="expected_custom",
        metavar="N",
        help="Expected number of custom Yara rules (CI validation, use with --list-rules)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a script file",
        epilog="Output options:\n"
               "  -o FILE         Write report to FILE instead of stdout\n"
               "  -f FORMAT       Specify output format (console, json, md)\n"
               "                  If -o is used without -f, format is auto-detected from extension",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    analyze_parser.add_argument(
        "file_path",
        type=str,
        help="The path to the script file to analyze"
    )
    analyze_parser.add_argument(
        "-o", "--output",
        type=str,
        dest="output_file",
        metavar="FILE",
        help="Write report to FILE instead of stdout (format auto-detected from extension)"
    )
    analyze_parser.add_argument(
        "-f", "--format",
        type=str,
        choices=['console', 'json', 'md'],
        dest="format",
        help="Output format: console (default), json, or md (markdown)"
    )
    analyze_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        dest="verbose",
        help="Show all findings including Low and Informational severity (default: only High/Critical)"
    )
    analyze_parser.add_argument(
        "--paranoia-level",
        type=int,
        choices=[1, 2, 3],
        default=1,
        dest="paranoia_level",
        metavar="LEVEL",
        help="Analysis sensitivity level: 1=Balanced (default), 2=Aggressive, 3=Maximum"
    )
    analyze_parser.add_argument(
        "--enable-llm",
        action="store_true",
        dest="enable_llm",
        help="Enable LLM-powered semantic analysis (requires Google Cloud credentials)"
    )
    analyze_parser.add_argument(
        "--llm-model",
        type=str,
        choices=['flash', 'pro', 'flash-thinking'],
        default='flash',
        dest="llm_model",
        metavar="MODEL",
        help="LLM model to use: flash=Fast (default), pro=Quality, flash-thinking=Experimental"
    )
    analyze_parser.add_argument(
        "--explain",
        action="store_true",
        dest="explain",
        help="Show detailed score breakdown explaining how the verdict was calculated"
    )

    args = parser.parse_args()

    # Handle --list-rules flag
    if args.list_rules:
        rules_dir = Path(__file__).parent.parent / "rules"
        try:
            engine = YaraEngine(rules_dir, strict_mode=args.strict_mode)
            compiled_rules, stats = engine.load_rules()

            print("Yara Rules Summary")
            print("=" * 40)
            print(f"Total rules discovered: {stats.total_files}")
            print(f"  - Public rules: {stats.public_count}")
            print(f"  - Custom rules: {stats.custom_count}")
            print(f"Rules loaded: {stats.loaded}")
            print(f"Rules skipped: {stats.skipped}")
            print(f"Load time: {stats.load_time_seconds:.3f}s")

            if stats.warnings:
                print("\nWarnings:")
                for warning in stats.warnings:
                    print(f"  ⚠️  {warning}")

            if stats.errors:
                print("\nSkipped Rules (compilation errors):")
                for error in stats.errors:
                    print(f"  ❌ {error}")

            # CI validation: check expected counts if provided
            exit_code = 0
            expected_public = getattr(args, 'expected_public', None)
            expected_custom = getattr(args, 'expected_custom', None)

            if expected_public is not None or expected_custom is not None:
                print("\nCI Validation:")

                if expected_public is not None:
                    public_status = "PASS" if stats.public_count == expected_public else "FAIL"
                    print(f"RULES_CHECK: type=public expected={expected_public} loaded={stats.public_count} status={public_status}")
                    if public_status == "FAIL":
                        exit_code = 1

                if expected_custom is not None:
                    custom_status = "PASS" if stats.custom_count == expected_custom else "FAIL"
                    print(f"RULES_CHECK: type=custom expected={expected_custom} loaded={stats.custom_count} status={custom_status}")
                    if custom_status == "FAIL":
                        exit_code = 1

            sys.exit(exit_code)
        except YaraRuleError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    if args.command == "analyze":
        # Read and identify script
        content, language, error = get_script_from_file(args.file_path)
        if error:
            print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)
        
        # Print informational messages
        print(f"Successfully read file: {args.file_path}")
        # Capitalize first letter only (e.g., "powershell" -> "PowerShell")
        lang_display = language[0].upper() + language[1:] if language else language
        print(f"Language identified: {lang_display}")
        
        # Determine output format
        output_format = args.format
        if not output_format and args.output_file:
            # Auto-detect from file extension
            output_format = detect_format_from_extension(args.output_file)
        elif not output_format:
            # Default to console
            output_format = 'console'
        
        # Validate format
        try:
            reporter = select_reporter(output_format)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        
        # Analyze script
        try:
            # Get strict mode flag (for Yara rule validation)
            strict_mode = getattr(args, 'strict_mode', False)
            analyzer = ScriptAnalyzer(Path(__file__).parent / 'patterns', strict_mode=strict_mode)
        except YaraRuleError as e:
            print(f"Error: Invalid Yara rule: {e.file_path}", file=sys.stderr)
            print(f"  {e.error}", file=sys.stderr)
            sys.exit(1)

        try:
            # Get paranoia level (default to 1 if not present)
            paranoia_level = getattr(args, 'paranoia_level', 1)
            # Get LLM settings
            enable_llm = getattr(args, 'enable_llm', False)
            llm_model = getattr(args, 'llm_model', 'flash')

            result, analysis_error = analyzer.analyze(
                content,
                language,
                include_llm=enable_llm,
                paranoia_level=paranoia_level,
                llm_model=llm_model
            )

            if analysis_error:
                print(f"Analysis error: {analysis_error}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Unexpected error during analysis: {e}", file=sys.stderr)
            sys.exit(1)
        
        # Generate and output report
        try:
            # Get verbose flag (default to False if not present)
            verbose = getattr(args, 'verbose', False)
            # Check for --explain flag
            explain = getattr(args, 'explain', False)

            # If --explain is set, use ExplainReporter instead
            if explain:
                reporter = ExplainReporter()
                output = reporter.generate(result)
                print(output)
                sys.exit(0)

            if args.output_file:
                # Write to file
                # For JSON reporter, write_to_file doesn't support verbose parameter
                # For Console and Markdown reporters, we need to generate first then write
                if output_format == 'json':
                    success, write_error = reporter.write_to_file(result, args.output_file)
                else:
                    # Generate with verbose flag, then write manually
                    output = reporter.generate(result, verbose=verbose)
                    try:
                        output_path = Path(args.output_file)
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        output_path.write_text(output, encoding='utf-8')
                        success = True
                        write_error = None
                    except Exception as e:
                        success = False
                        write_error = str(e)
                
                if not success:
                    print(f"Error writing report: {write_error}", file=sys.stderr)
                    sys.exit(1)
                print(f"Report written to: {args.output_file}")
            else:
                # Print to stdout
                if output_format == 'json':
                    output = reporter.generate(result)
                else:
                    output = reporter.generate(result, verbose=verbose)
                print(output)
        except Exception as e:
            print(f"Error generating report: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
