//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_NEW_BASIC_PARSER_HPP
#define BEAST_HTTP_NEW_BASIC_PARSER_HPP

#include <beast/core/error.hpp>
#include <beast/http/detail/new_basic_parser.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/optional.hpp>
#include <boost/assert.hpp>
#include <boost/utility/string_ref.hpp>
#include <utility>

#include <beast/http/basic_parser_v1.hpp> // hack for now
#include <beast/http/parser_v1.hpp> // hack for now

namespace beast {
namespace http {

template<bool isRequest, class Derived>
class new_basic_parser
    : private detail::new_basic_parser_base
{
    // Consider this message as having no body
    static unsigned constexpr flatOmitBody              = 1<<  0;

    // Parser will pause after reading the header
    static unsigned constexpr flagPauseBody             = 1<<  1;

    // Parser will pause after reading the header
    static unsigned constexpr flagSplitParse            = 1<<  2;

    // The parser has read at least one byte
    static unsigned constexpr flagGotSome               = 1<<  3;

    // Message semantics indicate a body is expected
    static unsigned constexpr flagHasBody               = 1<<  4;

    static unsigned constexpr flagDone                  = 1<<  5;
    static unsigned constexpr flagHaveHeader            = 1<<  6;
    static unsigned constexpr flagHTTP11                = 1<<  7;
    static unsigned constexpr flagNeedEOF               = 1<<  8;
    static unsigned constexpr flagExpectCRLF            = 1<<  9;
    static unsigned constexpr flagFinalChunk            = 1<< 10;

    static unsigned constexpr flagConnectionClose       = 1<< 11;
    static unsigned constexpr flagConnectionUpgrade     = 1<< 12;
    static unsigned constexpr flagConnectionKeepAlive   = 1<< 13;

    static unsigned constexpr flagContentLength         = 1<< 14;

    static unsigned constexpr flagChunked               = 1<< 15;

    static unsigned constexpr flagUpgrade               = 1<< 16;

    char* buf_ = nullptr;
    std::size_t buf_len_ = 0;

    std::uint64_t len_;     // size of chunk or body
    std::size_t skip_ = 0;  // search from here
    std::size_t x_;         // scratch variable
    unsigned f_ = 0;        // flags

    unsigned char version_; // LEGACY
    unsigned short status_; // LEGACY

protected:
    /// Default constructor
    new_basic_parser() = default;

public:
    /// Destructor
    ~new_basic_parser();

    /** Set options on the parser.

        @param args One or more parser options to set.
    */
#if GENERATING_DOCS
    template<class... Args>
    void
    set_option(Args&&... args)
#else
    template<class A1, class A2, class... An>
    void
    set_option(A1&& a1, A2&& a2, An&&... an)
#endif
    {
        set_option(std::forward<A1>(a1));
        set_option(std::forward<A2>(a2),
            std::forward<An>(an)...);
    }

    /// Set the body maximum size option
    void
    set_option(body_max_size const& o)
    {
        // VFALCO TODO
    }

    /// Set the header maximum size option
    void
    set_option(header_max_size const& o)
    {
        // VFALCO TODO
    }

    /// Set the skip body option.
    void
    set_option(skip_body const& opt)
    {
        if(opt.value)
            f_ |= flatOmitBody;
        else
            f_ &= ~flatOmitBody;
    }

    /** Returns `true` if the parser requires additional input.

        When this function returns `true`, the caller should
        perform one of the following actions in order for the
        parser to make forward progress:

        @li Commit additional bytes to the stream buffer, then
        call @write.

        @li Call @ref write_eof to indicate that the stream
        will never produce additional input.
    */
    bool
    need_more() const;

    /** Returns `true` if the parser is finished with the message.

        The message is finished when the header is parsed and
        one of the following is true:

        @li The @ref skip_body option is set

        @li The semantics of the message indicate there is no body.

        @li The complete, expected body was parsed.
    */
    bool
    is_done() const
    {
        return (f_ & flagDone) != 0;
    }

    unsigned
    flags() const
    {
        unsigned result = 0;
        if(f_ & flagUpgrade)
            result |= parse_flag::upgrade;
        if(f_ & flagConnectionClose)
            result |= parse_flag::connection_close;
        if(f_ & flagConnectionKeepAlive)
            result |= parse_flag::connection_keep_alive;
        if(f_ & flagConnectionUpgrade)
            result |= parse_flag::connection_upgrade;
        if(f_ & flagChunked)
            result |= parse_flag::chunked;
        return result;
    }

    /// Returns `true` if a complete header has been parsed.
    bool
    have_header() const
    {
        return (f_ & flagHaveHeader) != 0;
    }

    /** Returns `true` if the message end is indicated by eof.

        This function returns `true` if the semantics of the message
        require that the end of the message is signaled by an end
        of file. For example, if the message is a HTTP/1.0 message
        and the Content-Length is unspecified, the end of the message
        is indicated by an end of file.

        @note The return value is undefined unless a complete
        header has been parsed.
    */
    bool
    needs_eof() const
    {
        BOOST_ASSERT(have_header());
        return (f_ & flagNeedEOF) != 0;
    }

    /** Returns the major HTTP version number.

        Examples:
            * Returns 1 for HTTP/1.1
            * Returns 1 for HTTP/1.0

        @return The HTTP major version number.
    */
    unsigned
    http_major() const
    {
        BOOST_ASSERT(have_header());
        return version_ / 10;
    }

    /** Returns the minor HTTP version number.

        Examples:
            * Returns 1 for HTTP/1.1
            * Returns 0 for HTTP/1.0

        @return The HTTP minor version number.
    */
    unsigned
    http_minor() const
    {
        BOOST_ASSERT(have_header());
        return version_ % 10;
    }

    /** Returns `true` if the message is an upgrade message.

        @note The return value is undefined unless a complete
        header has been parsed.
    */
    bool
    upgrade() const
    {
        return (f_ & flagConnectionUpgrade) != 0;
    }

    /** Returns the numeric HTTP Status-Code of a response.

        @return The Status-Code.
    */
    unsigned
    status_code() const
    {
        return status_;
    }

    /** Returns `true` if keep-alive is specified

        @note The return value is undefined unless a complete
        header has been parsed.
    */
    bool
    keep_alive() const;

    template<class ConstBufferSequence>
    std::size_t
    write(ConstBufferSequence const& buffers, error_code& ec);

    std::size_t
    write(boost::asio::const_buffers_1 const& buffer,
        error_code& ec);

    /** Inform the parser that the end of file was reached.

        HTTP needs to know where the end of the stream is. For
        example, sometimes servers send responses without
        Content-Length and expect the client to consume input
        (for the body) until EOF. Callbacks and errors will still
        be processed as usual.

        @note This is typically called when a socket read returns
        the end of file error.
    */
    void
    write_eof(error_code& ec);




    /** Returns the optional value of Content-Length if known.

        @note The return value is undefined unless a complete
        header has been parsed.
    */
    boost::optional<std::uint64_t>
    content_length() const
    {
        BOOST_ASSERT(have_header());
        if(! (f_ & flagContentLength))
            return boost::none;
        return len_;
    }

    /** Returns the number of body bytes remaining in this chunk.
    */
    std::uint64_t
    remain() const
    {
        BOOST_ASSERT(have_header());
        if(f_ & (flagContentLength | flagChunked))
            return len_;
        // VFALCO This is ugly
        return 65536;
    }

    /** Transfer body octets from buffer to the reader
    */
    template<class Reader, class DynamicBuffer>
    void
    write_body(Reader& r,
        DynamicBuffer& dynabuf, error_code& ec);

    /** Consume body bytes from the current chunk.
    */
    void
    consume(std::uint64_t n)
    {
        len_ -= n;
    }

protected:
    /** Set the split parse option.

        When the derived class enables the split parse,
        the function @ref need_more will return `false`
        when a complete header has been received.
    */
    void
    split(bool value)
    {
        if(value)
            f_ |= flagSplitParse;
        else
            f_ &= ~flagSplitParse;
    }

private:
    inline
    Derived&
    impl()
    {
        return *static_cast<Derived*>(this);
    }

    /** Returns `true` if the Transfer-Encoding specifies chunked

        @note The return value is undefined unless a complete
        header has been parsed.
    */
    bool
    is_chunked() const
    {
        BOOST_ASSERT(have_header());
        return (f_ & flagChunked) != 0;
    }

    template<class ConstBufferSequence>
    boost::string_ref
    maybe_flatten(
        ConstBufferSequence const& buffers);

    void
    maybe_done(error_code& ec);

    void
    parse_startline(char const*& it,
        int& version, int& status,
            error_code& ec, std::true_type);

    void
    parse_startline(char const*& it,
        int& version, int& status,
            error_code& ec, std::false_type);

    void
    parse_fields(char const*& it,
        char const* last, error_code& ec);

    void
    do_field(
        boost::string_ref const& name,
            boost::string_ref const& value,
                error_code& ec);

    std::size_t
    parse_header(char const* p,
        std::size_t n, error_code& ec);

    void
    do_header(int status, std::true_type);

    void
    do_header(int status, std::false_type);

    std::size_t
    parse_body(char const* p,
        std::size_t n, error_code& ec);

    std::size_t
    parse_chunk(char const* p,
        std::size_t n, error_code& ec);
};

} // http
} // beast

#include <beast/http/impl/new_basic_parser.ipp>

#endif
