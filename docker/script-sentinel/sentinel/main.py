import argparse
import sys
from pathlib import Path
from sentinel.extractor import get_script_from_file
from sentinel.analyzer import ScriptAnalyzer
from sentinel.reporters import ConsoleReporter, JSONReporter, MarkdownReporter


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

    args = parser.parse_args()

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
            analyzer = ScriptAnalyzer(Path(__file__).parent / 'patterns')
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
