//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_IMPL_NEW_BASIC_PARSER_IPP
#define BEAST_HTTP_IMPL_NEW_BASIC_PARSER_IPP

#include <beast/core/buffer_concepts.hpp>
#include <beast/core/detail/ci_char_traits.hpp>
#include <beast/core/detail/clamp.hpp>
#include <beast/core/detail/type_traits.hpp>
#include <beast/http/new_error.hpp>
#include <beast/http/rfc7230.hpp>
#include <boost/asio/buffer.hpp>
#include <algorithm>

namespace beast {
namespace http {

template<bool isRequest, class Derived>
new_basic_parser<isRequest, Derived>::
~new_basic_parser()
{
    if(buf_)
        delete[] buf_;
}

template<bool isRequest, class Derived>
bool
new_basic_parser<isRequest, Derived>::
need_more() const
{
    if(! (f_ & flagHaveHeader))
        return true;
    if(! (f_ & flagNeedBody))
        return false;
    if(f_ & (
            flagPauseBody  | flagSkipBody |
            flagSplitParse | flagDone))
        return false;
    return true;
}

template<bool isRequest, class Derived>
bool
new_basic_parser<isRequest, Derived>::
keep_alive() const
{
    BOOST_ASSERT(have_header());
    if(f_ & flagHTTP11)
    {
        if(f_ & flagConnectionClose)
            return false;
    }
    else
    {
        if(! (f_ & flagConnectionKeepAlive))
            return false;
    }
    return ! needs_eof();
}

template<bool isRequest, class Derived>
template<class ConstBufferSequence>
std::size_t
new_basic_parser<isRequest, Derived>::
write(ConstBufferSequence const& buffers,
    error_code& ec)
{
    static_assert(is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence not met");
    auto const buffer = maybe_flatten(buffers);
    return write(boost::asio::const_buffers_1{
        buffer.data(), buffer.size()}, ec);
}

template<bool isRequest, class Derived>
std::size_t
new_basic_parser<isRequest, Derived>::
write(boost::asio::const_buffers_1 const& buffer,
    error_code& ec)
{
    BOOST_ASSERT(! complete());
    using boost::asio::buffer_cast;
    using boost::asio::buffer_size;
    boost::string_ref s0{
        buffer_cast<char const*>(*buffer.begin()),
            buffer_size(*buffer.begin())};
    auto s = s0;
    if(! have_header())
    {
        if(! s.empty())
            f_ |= flagGotSome;
        auto const n = parse_header(
            s.data(), s.size(), ec);
        if(n == 0)
            return 0;
        BOOST_ASSERT(! ec);
        BOOST_ASSERT(have_header());
        s.remove_prefix(n);
    }
    if(is_chunked())
    {
        while(! complete() && ! s.empty())
        {
            if(len_ == 0)
            {
                auto n = parse_chunk(
                    s.data(), s.size(), ec);
                if(n == 0)
                    return 0;
                BOOST_ASSERT(! ec);
                s.remove_prefix(n);
            }
            else
            {
                auto n = parse_body(
                    s.data(), s.size(), ec);
                if(ec)
                    return 0;
                s.remove_prefix(n);
            }
        }
    }
    else
    {
        while(! complete() && ! s.empty())
        {
            auto n = parse_body(
                s.data(), s.size(), ec);
            if(ec)
                return 0;
            s.remove_prefix(n);
        }
    }
    return s0.size() - s.size();
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
write_eof(error_code& ec)
{
    if(! (f_ & flagHaveHeader))
    {
        ec = error::partial_message;
        return;
    }

    if(f_ & (flagContentLength | flagChunked))
    {
        if(! (f_ & flagDone))
        {
            ec = error::partial_message;
            return;
        }
    }
    else
    {
        f_ |= flagDone;
    }
}

template<bool isRequest, class Derived>
template<class Reader, class DynamicBuffer>
void
new_basic_parser<isRequest, Derived>::
write_body(Reader& r,
    DynamicBuffer& dynabuf, error_code& ec)
{
    using boost::asio::buffer_copy;
    auto const n = beast::detail::clamp(
        len_, dynabuf.size());
    auto const b = r.prepare(n, ec);
    if(ec)
        return;
    auto const len = buffer_copy(
        b, dynabuf.data(), n);
    r.commit(len, ec);
    if(ec)
        return;
    dynabuf.consume(len);
    if(f_ & flagContentLength)
    {
        len_ -= len;
        if(len_ == 0)
            f_ |= flagDone;
    }
    else if(f_ & flagChunked)
    {
        len_ -= len;
    }
}

template<bool isRequest, class Derived>
template<class ConstBufferSequence>
boost::string_ref
new_basic_parser<isRequest, Derived>::
maybe_flatten(
    ConstBufferSequence const& buffers)
{
    using boost::asio::buffer;
    using boost::asio::buffer_cast;
    using boost::asio::buffer_copy;
    using boost::asio::buffer_size;

    auto const it = buffers.begin();
    auto const last = buffers.end();
    if(it == last)
        return {nullptr, 0};
    if(std::next(it) == last)
    {
        // single buffer
        auto const b = *it;
        return {buffer_cast<char const*>(b),
            buffer_size(b)};
    }
    auto const len = buffer_size(buffers);
    if(len > buf_len_)
    {
        // reallocate
        if(buf_)
            delete[] buf_;
        buf_ = new char[len];
        buf_len_ = len;
    }
    // flatten
    buffer_copy(
        buffer(buf_, buf_len_), buffers);
    return {buf_, buf_len_};
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
parse_startline(char const*& it,
    int& version, int& status,
        error_code& ec, std::true_type)
{
/*
    request-line   = method SP request-target SP HTTP-version CRLF
    method         = token
*/
    auto const method = parse_method(it);
    if(method.empty())
    {
        ec = error::bad_method;
        return;
    }
    if(*it++ != ' ')
    {
        ec = error::bad_method;
        return;
    }

    auto const path = parse_path(it);
    if(path.empty())
    {
        ec = error::bad_path;
        return;
    }
    if(*it++ != ' ')
    {
        ec = error::bad_path;
        return;
    }

    version = parse_version(it);
    if(version < 0 || ! parse_crlf(it))
    {
        ec = error::bad_version;
        return;
    }
    version_ = version;

    impl().on_request(
        method, path, version, ec);
    if(ec)
        return;
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
parse_startline(char const*& it,
    int& version, int& status,
        error_code& ec, std::false_type)
{
/*
     status-line    = HTTP-version SP status-code SP reason-phrase CRLF
     status-code    = 3*DIGIT
     reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
*/
    version = parse_version(it);
    if(version < 0 || *it != ' ')
    {
        ec = error::bad_version;
        return;
    }
    ++it;
    version_ = version;

    status = parse_status(it);
    if(status < 0 || *it != ' ')
    {
        ec = error::bad_status;
        return;
    }
    ++it;
    status_ = status;

    auto const reason = parse_reason(it);
    if(! parse_crlf(it))
    {
        ec = error::bad_reason;
        return;
    }

    impl().on_response(
        status, reason, version, ec);
    if(ec)
        return;
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
parse_fields(char const*& it,
    char const* last, error_code& ec)
{
/*  header-field   = field-name ":" OWS field-value OWS

    field-name     = token
    field-value    = *( field-content / obs-fold )
    field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    field-vchar    = VCHAR / obs-text

    obs-fold       = CRLF 1*( SP / HTAB )
                   ; obsolete line folding
                   ; see Section 3.2.4
*/
    for(;;)
    {
        auto term = find_crlf(it, last);
        BOOST_ASSERT(! term.empty());
        if(it == term.begin())
        {
            it = term.end();
            break;
        }
        auto const name = parse_name(it);
        if(name.empty())
        {
            ec = error::bad_field;
            return;
        }
        if(*it++ != ':')
        {
            ec = error::bad_field;
            return;
        }
        if(*term.end() != ' ' &&
            *term.end() != '\t')
        {
            detail::skip_ows(it, term.begin());
            auto it2 = term.begin();
            detail::skip_ows_rev(it2, it);
            auto const value =
                make_string(it, it2);
            do_field(name, value, ec);
            if(ec)
                return;
            impl().on_field(name, value, ec);
            if(ec)
                return;
            it = term.end();
        }
        else
        {
            // obs-fold
            for(;;)
            {
                detail::skip_ows(it, term.begin());
                if(it != term.begin())
                    break;
                it = term.end();
                if(*term.end()!= ' ' &&
                        *term.end() != '\t')
                    break;
                term = find_crlf(it, last);
            }
            std::string s;
            if(it != term.end())
            {
                s.append(it, term.begin());
                it = term.end();
                for(;;)
                {
                    if(*it != ' ' && *it != '\t')
                        break;
                    s.push_back(' ');
                    detail::skip_ows(it, term.begin());
                    term = find_crlf(it, last);
                    if(it != term.begin())
                        s.append(it, term.begin());
                    it = term.end();
                }
            }
            boost::string_ref value{
                s.data(), s.size()};
            do_field(name, value, ec);
            if(ec)
                return;
            impl().on_field(name, value, ec);
            if(ec)
                return;
        }
    }
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
do_field(
    boost::string_ref const& name,
        boost::string_ref const& value,
            error_code& ec)
{
    // Connection
    if(strieq("connection", name) ||
        strieq("proxy-connection", name))
    {
        auto const list = opt_token_list{value};
        if(! validate_list(list))
        {
            // VFALCO Should this be a field specific error?
            ec = error::bad_value;
            return;
        }
        for(auto const& s : list)
        {
            if(strieq("close", s))
            {
                f_ |= flagConnectionClose;
                continue;
            }

            if(strieq("keep-alive", s))
            {
                f_ |= flagConnectionKeepAlive;
                continue;
            }

            if(strieq("upgrade", s))
            {
                f_ |= flagConnectionUpgrade;
                continue;
            }
        }
        return;
    }

    for(auto it = value.begin();
        it != value.end(); ++it)
    {
        if(! is_text(*it))
        {
            ec = error::bad_value;
            return;
        }
    }

    // Content-Length
    if(strieq("content-length", name))
    {
        if(f_ & flagContentLength)
        {
            // duplicate
            ec = error::bad_content_length;
            return;
        }

        if(f_ & flagChunked)
        {
            // conflicting field
            ec = error::bad_content_length;
            return;
        }

        std::uint64_t v;
        if(! parse_dec(
            value.begin(), value.end(), v))
        {
            ec = error::bad_content_length;
            return;
        }

        len_ = v;
        f_ |= flagContentLength;
        return;
    }

    // Transfer-Encoding
    if(strieq("transfer-encoding", name))
    {
        if(f_ & flagChunked)
        {
            // duplicate
            ec = error::bad_transfer_encoding;
            return;
        }

        if(f_ & flagContentLength)
        {
            // conflicting field
            ec = error::bad_transfer_encoding;
            return;
        }

        auto const v = token_list{value};
        auto const it = std::find_if(v.begin(), v.end(),
            [&](typename token_list::value_type const& s)
            {
                return strieq("chunked", s);
            });
        if(it == v.end())
            return;
        if(std::next(it) != v.end())
            return;
        len_ = 0;
        f_ |= flagChunked;
        return;
    }

    // Upgrade
    if(strieq("upgrade", name))
    {
        f_ |= flagUpgrade;
        ec = {};
        return;
    }
}

template<bool isRequest, class Derived>
std::size_t
new_basic_parser<isRequest, Derived>::
parse_header(char const* p,
    std::size_t n, error_code& ec)
{
    if(n < 4)
        return 0;
    auto const term =
        find_2x_crlf(p + skip_, p + n);
    if(term.empty())
    {
        skip_ = n - 3;
        return 0;
    }

    int version;
    int status; // ignored for requests

    skip_ = 0;
    n = term.end() - p;
    parse_startline(p, version, status, ec,
        std::integral_constant<
            bool, isRequest>{});
    if(ec)
        return 0;
    if(version >= 11)
        f_ |= flagHTTP11;

    parse_fields(p, term.end(), ec);
    if(ec)
        return 0;
    BOOST_ASSERT(p == term.end());

    f_ |= flagHaveHeader; // set before on_header
    do_header(status, std::integral_constant<
        bool, isRequest>{});
    impl().on_header(ec);
    if(ec)
        return 0;
    return n;
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
do_header(int, std::true_type)
{
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
do_header(int status, std::false_type)
{
    // RFC 7230 section 3.3
    // https://tools.ietf.org/html/rfc7230#section-3.3
    if( status  / 100 == 1 ||   // 1xx e.g. Continue
        status == 204 ||        // No Content
        status == 304 ||        // Not Modified
        (f_ & flagSkipBody))    // e.g. response to a HEAD request
        return;

    if(f_ & (flagChunked | flagContentLength))
        return;

    f_ |= flagNeedEOF;
}

//    return ! (f_ & (flagChunked + flagContentLength));

template<bool isRequest, class Derived>
std::size_t
new_basic_parser<isRequest, Derived>::
parse_body(char const* p,
    std::size_t n, error_code& ec)
{
    if(f_ & flagNeedEOF)
    {
        impl().on_body(
            boost::string_ref{p, n}, ec);
        if(ec)
            return 0;
        return n;
    }

    n = beast::detail::clamp(n, len_);
    impl().on_body(
        boost::string_ref{p, n}, ec);
    if(ec)
        return 0;
    len_ -= n;
    if(len_ == 0 && ! is_chunked())
        f_ |= flagDone;
    return n;
}

template<bool isRequest, class Derived>
std::size_t
new_basic_parser<isRequest, Derived>::
parse_chunk(char const* p,
    std::size_t n, error_code& ec)
{
/*
    chunked-body   = *chunk last-chunk trailer-part CRLF

    chunk          = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
    last-chunk     = 1*("0") [ chunk-ext ] CRLF
    trailer-part   = *( header-field CRLF )

    chunk-size     = 1*HEXDIG
    chunk-data     = 1*OCTET ; a sequence of chunk-size octets
    chunk-ext      = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
    chunk-ext-name = token
    chunk-ext-val  = token / quoted-string
*/

    auto const first = p;
    auto const last = p + n;

    // Treat the last CRLF in a chunk as
    // part of the next chunk, so it can
    // be parsed in one call instead of two.
    if(f_ & flagExpectCRLF)
    {
        if(n < 2)
            return 0;
        if(! parse_crlf(p))
        {
            ec = error::bad_chunk;
            return 0;
        }
        n -= 2;
    }

    boost::string_ref term;

    if(! (f_ & flagFinalChunk))
    {
        if(n < 2)
            return 0;
        term = find_crlf(p + skip_, last);
        if(term.empty())
        {
            skip_ = n - 1;
            return 0;
        }
        std::uint64_t v;
        if(! parse_hex(p, v))
        {
            ec = error::bad_chunk;
            return 0;
        }
        if(v != 0)
        {
            if(*p == ';')
            {
                // VFALCO We need to parse the chunk
                // extension to validate it here.
                impl().on_chunk(v,
                    make_string(
                        p, term.begin()), ec);
                if(ec)
                    return 0;
            }
            else if(p != term.begin())
            {
                ec = error::bad_chunk;
                return 0;
            }
            p = term.end();
            len_ = v;
            skip_ = 0;
            f_ |= flagExpectCRLF;
            return p - first;
        }

        // This is the offset from the buffer
        // to the beginning of the first '\r\n'
        x_ = term.begin() - first;
        skip_ = x_;
    }

    term = find_2x_crlf(first + skip_, last);
    if(term.empty())
    {
        if(n > 3)
            skip_ = (last - first) - 3;
        return 0;
    }
        
    if(f_ & flagFinalChunk)
    {
        // We are parsing the value again
        // to advance p to the right place.
        std::uint64_t v;
        auto const result = parse_hex(p, v);
        BOOST_ASSERT(result && v == 0);
        beast::detail::ignore_unused(result);
        beast::detail::ignore_unused(v);
    }
    else
    {
        f_ |= flagFinalChunk;
    }

    if(*p == ';')
    {
        impl().on_chunk(0,
            make_string(
                p, first + x_), ec);
        if(ec)
            return 0;
        p = first + x_;
    }
    if(! parse_crlf(p))
    {
        ec = error::bad_chunk;
        return 0;
    }
    parse_fields(p, term.end(), ec);
    if(ec)
        return 0;
    BOOST_ASSERT(p == term.end());
    f_ |= flagDone;
    return p - first;
}

} // http
} // beast

#endif
