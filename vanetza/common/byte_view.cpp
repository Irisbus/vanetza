#include <vanetza/common/byte_view.hpp>
#include <vanetza/common/byte_buffer_convertible.hpp>
#include <cassert>
#include <limits>

namespace vanetza
{

namespace
{

boost::iterator_range<byte_view_iterator>
make_safe_range(const ByteBuffer::const_iterator& begin, const ByteBuffer::const_iterator& end)
{
    if (begin < end) {
        byte_view_iterator vbegin { begin };
        byte_view_iterator vend { std::next(vbegin, std::distance(begin, end)) };
        return boost::iterator_range<byte_view_iterator> { vbegin, vend };
    } else {
        byte_view_iterator empty;
        return boost::iterator_range<byte_view_iterator> { empty, empty };
    }
}

}

byte_view_range::byte_view_range(const ByteBuffer::const_iterator& begin, const ByteBuffer::const_iterator& end) :
    iterator_range(make_safe_range(begin, end))
{
}

byte_view_range::byte_view_range(const byte_view_iterator& begin, const byte_view_iterator& end) :
    iterator_range(begin, end)
{
}

byte_view_range::byte_view_range(ByteBuffer&& _buffer) :
    iterator_range(make_safe_range(_buffer.begin(), _buffer.end())), buffer(std::move(_buffer))
{
}

ByteBuffer::const_pointer byte_view_range::data() const
{
    auto begin = this->begin();
    return begin != this->end() ? begin.raw() : nullptr;
}

ByteBuffer::value_type byte_view_range::operator[](size_type pos) const
{
    assert(!std::numeric_limits<size_type>::is_signed || pos >= 0);
    assert(pos < size());
    return begin()[pos];
}

byte_view_range create_byte_view(ByteBuffer&& buffer)
{
    return byte_view_range { std::move(buffer) };
}

byte_view_range create_byte_view(const ByteBuffer& buffer)
{
    return byte_view_range { buffer.begin(), buffer.end() };
}

byte_view_range create_byte_view(const ByteBufferConvertible& convertible)
{
    ByteBuffer buffer;
    convertible.convert(buffer);
    return byte_view_range { std::move(buffer) };
}

} // namespace vanetza
